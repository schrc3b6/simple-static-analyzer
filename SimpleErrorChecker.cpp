#include <clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h>
#include <clang/StaticAnalyzer/Core/BugReporter/BugType.h>
#include <clang/StaticAnalyzer/Core/BugReporter/BugReporterVisitors.h>
#include <clang/StaticAnalyzer/Core/Checker.h>
#include <clang/StaticAnalyzer/Frontend/CheckerRegistry.h>
#include <clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h>
#include <clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h>
#include <clang/StaticAnalyzer/Core/PathSensitive/SymExpr.h>
#include <iostream>
#include <utility>

using namespace clang;
using namespace ento;

namespace {
typedef SmallVector<SymbolRef, 2> SymbolVector;

struct ErrorCheckedState {
private:
  enum Kind { Unchecked } K;
  ErrorCheckedState(Kind InK) : K(InK) { }

public:
  bool isUnchecked() const { return K == Unchecked; }

  static ErrorCheckedState getUnchecked() { return ErrorCheckedState(Unchecked); }

  bool operator==(const ErrorCheckedState &X) const {
    return K == X.K;
  }
  void Profile(llvm::FoldingSetNodeID &ID) const {
    ID.AddInteger(K);
  }
};

class SimpleErrorChecker : public Checker<check::PostCall,
                                          check::PreCall,
                                          check::PointerEscape,
                                          check::Location,
                                          check::DeadSymbols> {
  CallDescription mallocFn, callocFn;

  std::unique_ptr<BugType> UseBeforCheckBugType;

  void reportUseBeforCheck(SymbolRef FileDescSym,
                         SourceRange range,
                         CheckerContext &C) const;

public:
  SimpleErrorChecker();

  /// Process fopen.
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

  void checkLocation(SVal Loc, bool IsLoad, const Stmt *S,
                     CheckerContext &) const; 

  void checkDeadSymbols(SymbolReaper &SR, CheckerContext &C) const;

  ProgramStateRef checkPointerEscape(ProgramStateRef State,
                                        const InvalidatedSymbols &Escaped,
                                        const CallEvent *Call,
                                        PointerEscapeKind Kind) const;
};

} // end anonymous namespace

REGISTER_MAP_WITH_PROGRAMSTATE(ErrorCheckMap, SymbolRef, ErrorCheckedState)

namespace {
class StopTrackingCallback final : public SymbolVisitor {
  ProgramStateRef state;
public:
  StopTrackingCallback(ProgramStateRef st) : state(std::move(st)) {}
  ProgramStateRef getState() const { return state; }

  bool VisitSymbol(SymbolRef sym) override {
    state = state->remove<ErrorCheckMap>(sym);
    return true;
  }
};
} // end anonymous namespace

class MyVisitor final : public BugReporterVisitor{
    protected:
        SymbolRef Sym;
    public:
        void Profile ( llvm :: FoldingSetNodeID & ID ) const {
            ID.AddPointer(Sym);
        }
        MyVisitor(SymbolRef S ) : Sym(S){}

        PathDiagnosticPieceRef VisitNode(const ExplodedNode *N,
                                         BugReporterContext &BRC,
                                         PathSensitiveBugReport &BR) override;
};

    PathDiagnosticPieceRef MyVisitor::VisitNode(const ExplodedNode *N,
                                         BugReporterContext &BRC,
                                         PathSensitiveBugReport &BR) {

  ProgramStateRef state = N->getState();
  ProgramStateRef statePrev = N->getFirstPred()->getState();

  const ErrorCheckedState *TrackedNullab = state->get<ErrorCheckMap>(Sym);
  const ErrorCheckedState *TrackedNullabPrev = statePrev->get<ErrorCheckMap>(Sym);

  if (!TrackedNullab)
    return nullptr;

  if (TrackedNullabPrev &&
      TrackedNullabPrev == TrackedNullab)
    return nullptr;

  const Stmt *S = N->getStmtForDiagnostics();
  if (!S){
      return nullptr;
  }

  StringRef Msg;
  std::unique_ptr<StackHintGeneratorForSymbol> StackHint = nullptr;

      Msg = "Memory is allocated";
      StackHint = std::make_unique<StackHintGeneratorForSymbol>(
          Sym, "Returned allocated memory");

    PathDiagnosticLocation Pos= PathDiagnosticLocation(S, BRC.getSourceManager(),N->getLocationContext());
    auto P = std::make_shared<PathDiagnosticEventPiece>(Pos, Msg, true);
    BR.addCallStackHint(P, std::move(StackHint));
    return P;
}

SimpleErrorChecker::SimpleErrorChecker()
    : mallocFn("malloc"), callocFn("calloc") {
  UseBeforCheckBugType.reset(
      new BugType(this, "Use variable before allocation check", "Unix Stream API Error"));
}

void SimpleErrorChecker::checkPostCall(const CallEvent &Call,
                                        CheckerContext &C) const {
  if (!Call.isGlobalCFunction())
    return;

  if (!Call.isCalled(mallocFn) && !Call.isCalled(callocFn))
    return;


  // Get the symbolic value corresponding to the file handle.
  SymbolRef AllocVar = Call.getReturnValue().getAsSymbol();
  if (!AllocVar)
    return;

  // Generate the next transition (an edge in the exploded graph).
  ProgramStateRef State = C.getState();
  State = State->set<ErrorCheckMap>(AllocVar, ErrorCheckedState::getUnchecked());
  C.addTransition(State);
}

void SimpleErrorChecker::checkLocation(SVal loc, bool IsLoad, const Stmt *S,
                                      CheckerContext &C) const {

  ProgramStateRef State = C.getState();
  SymbolVector LeakedStreams;
  SymbolRef sym = loc.getAsLocSymbol();

  if(!sym){
    return;
  }
  
  const ErrorCheckedState *symState = State->get<ErrorCheckMap>(sym);
  if(symState && symState->isUnchecked()){

    ConstraintManager &CMgr = State->getConstraintManager();
    ConditionTruthVal Unchecked = CMgr.isNull(State, sym);

    if(!Unchecked.isConstrainedFalse()){
      SourceRange range = S->getSourceRange();
      reportUseBeforCheck(sym,range, C);
    }
    State = State->remove<ErrorCheckMap>(sym);
  }
}

void SimpleErrorChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  for(unsigned int i=0; i < Call.getNumArgs();i++){
    SymbolRef sym = Call.getArgSVal(i).getAsSymbol();
    if (sym){
      const ErrorCheckedState *symState = State->get<ErrorCheckMap>(sym);
      if(symState && symState->isUnchecked()){
        ConstraintManager &CMgr = State->getConstraintManager();
        ConditionTruthVal Unchecked = CMgr.isNull(State, sym);

        if(!Unchecked.isConstrainedFalse()){
          SourceRange range = Call.getSourceRange();
          reportUseBeforCheck(sym,range, C);
        }
        State = State->remove<ErrorCheckMap>(sym);
      }
    }
  }
}

void SimpleErrorChecker::reportUseBeforCheck(SymbolRef Sym,
                                            SourceRange range,
                                            CheckerContext &C) const {
  ExplodedNode *ErrNode = C.generateErrorNode();
  if (!ErrNode)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *UseBeforCheckBugType, "Using Variable before checking it for Errors", ErrNode);
  R->addRange(range);
  R->markInteresting(Sym);
  R->addVisitor(std::make_unique<MyVisitor>(Sym));
  C.emitReport(std::move(R));
}


void SimpleErrorChecker::checkDeadSymbols(SymbolReaper &SR, CheckerContext &C) const {

  ProgramStateRef State = C.getState();
  ErrorCheckMapTy TrackedStreams = State->get<ErrorCheckMap>();
  for (ErrorCheckMapTy::iterator I = TrackedStreams.begin(),
                             E = TrackedStreams.end(); I != E; ++I) {
    SymbolRef Sym = I->first;
    bool IsSymDead = SR.isDead(Sym);
    // Remove the dead symbol from the streams map.
    if (IsSymDead){
      State = State->remove<ErrorCheckMap>(Sym);
    }
  } 
}

ProgramStateRef
SimpleErrorChecker::checkPointerEscape(ProgramStateRef State,
                                        const InvalidatedSymbols &Escaped,
                                        const CallEvent *Call,
                                        PointerEscapeKind Kind) const {
  for (InvalidatedSymbols::const_iterator I = Escaped.begin(),
                                          E = Escaped.end();
                                          I != E; ++I) {
    SymbolRef Sym = *I;
    State = State->remove<ErrorCheckMap>(Sym);
  }
  return State;
}

// Register plugin!
extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SimpleErrorChecker>(
      "example.ErrorChecker",
      "Detects mismatches between memory allocations and deallocations",
      "",false);
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/*
void ento::registerSimpleErrorChecker(CheckerManager &mgr) {
  mgr.registerChecker<SimpleErrorChecker>();
}

// This checker should be enabled regardless of how language options are set.
bool ento::shouldRegisterSimpleErrorChecker(const CheckerManager &mgr) {
  return true;
}
*/
