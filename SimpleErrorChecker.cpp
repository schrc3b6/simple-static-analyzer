//===-- SimpleStreamChecker.cpp -----------------------------------------*- C++ -*--//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// Defines a checker for proper use of fopen/fclose APIs.
//   - If a file has been closed with fclose, it should not be accessed again.
//   Accessing a closed file results in undefined behavior.
//   - If a file was opened with fopen, it must be closed with fclose before
//   the execution ends. Failing to do so results in a resource leak.
//
//===----------------------------------------------------------------------===//

#include <clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h>
#include <clang/StaticAnalyzer/Core/BugReporter/BugType.h>
#include <clang/StaticAnalyzer/Core/BugReporter/BugReporterVisitors.h>
#include <clang/StaticAnalyzer/Core/Checker.h>
#include <clang/StaticAnalyzer/Frontend/CheckerRegistry.h>
#include <clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h>
#include <clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h>
#include <clang/StaticAnalyzer/Core/PathSensitive/SymExpr.h>
//#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
//#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
//#include "clang/StaticAnalyzer/Core/BugReporter/BugReporterVisitors.h"
//#include "clang/StaticAnalyzer/Core/Checker.h"
//#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
//#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
//#include "clang/StaticAnalyzer/Core/PathSensitive/SymExpr.h"
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

  /*
  void reportLeaks(ArrayRef<SymbolRef> LeakedStreams,
                                      CheckerContext &C,
                                      ExplodedNode *ErrNode) const;
                                      */

  //bool guaranteedNotToCloseFile(const CallEvent &Call) const;

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

/// The state of the checker is a map from tracked stream symbols to their
/// state. Let's store it in the ProgramState.
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
    //Pos.dump();
    auto P = std::make_shared<PathDiagnosticEventPiece>(Pos, Msg, true);
    BR.addCallStackHint(P, std::move(StackHint));
    return P;
}

SimpleErrorChecker::SimpleErrorChecker()
    : mallocFn("malloc"), callocFn("calloc") {
  // Initialize the bug types.
  UseBeforCheckBugType.reset(
      new BugType(this, "Use variable before allocation check", "Unix Stream API Error"));
}

void SimpleErrorChecker::checkPostCall(const CallEvent &Call,
                                        CheckerContext &C) const {
  std::cout << "test";
  if (!Call.isGlobalCFunction())
    return;

  Call.dump();
  if (!Call.isCalled(mallocFn) && !Call.isCalled(callocFn))
    return;

  std::cout << "test2";

  // Get the symbolic value corresponding to the file handle.
  SymbolRef AllocVar = Call.getReturnValue().getAsSymbol();
  if (!AllocVar)
    return;

  std::cout << "test3";
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


/*
  std::cout << "\n\n State:\n";
  State->dump();
  std::cout << "\n\n Statement:\n";
  S->dump();
  std::cout << "\n\n Location:\n";
  loc.dump();
  std::cout << "\n\n locSymbol:\n";
  if(loc.getAsLocSymbol()){
    loc.getAsLocSymbol()->dump();
  std::cout << "\n\n StateMap:\n";
  const ErrorCheckedState *SS = State->get<ErrorCheckMap>(loc.getAsLocSymbol());
  std::cout << "isUnchecked: " << SS->isUnchecked();
          }

  std::cout << "\n\n Constraints:\n";
  ErrorCheckMapTy TrackedStreams = State->get<ErrorCheckMap>();
  for (ErrorCheckMapTy::iterator I = TrackedStreams.begin(),
                             E = TrackedStreams.end(); I != E; ++I) {
    SymbolRef Sym = I->first;

  std::cout << "\n\n Symbols:\n";
  Sym->dump();
  //ProgramStateRef State = C.getState();
  ConstraintManager &CMgr = State->getConstraintManager();
  
  //SymbolRef Sym = val.getAsSymbol();
  ConditionTruthVal Unchecked = CMgr.isNull(State, Sym);
  
  std::cout << "\n\n Constraint isNull isFalse:\n";
  std::cout << Unchecked.isConstrainedFalse();
  }
}
*/

void SimpleErrorChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  Call.dump();
  for(unsigned int i=0; i < Call.getNumArgs();i++){
    SymbolRef sym = Call.getArgSVal(i).getAsSymbol();
    if (sym){
      const ErrorCheckedState *symState = State->get<ErrorCheckMap>(sym);
      std::cout << "test4";
      if(symState && symState->isUnchecked()){
        std::cout << "test5";
        ConstraintManager &CMgr = State->getConstraintManager();
        ConditionTruthVal Unchecked = CMgr.isNull(State, sym);

        std::cout << "\n\nValue:\n";
        std::cout << Unchecked.getValue();
        if(!Unchecked.isConstrainedFalse()){
          std::cout << "test6";
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
  // We reached a bug, stop exploring the path here by generating a sink.
  ExplodedNode *ErrNode = C.generateErrorNode();
  // If we've already reached this node on another path, return.
  if (!ErrNode)
    return;

          std::cout << "test7";
  // Generate the report.
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
    if (IsSymDead)
      State = State->remove<ErrorCheckMap>(Sym);
  } 
}

// If the pointer we are tracking escaped, do not track the symbol as
// we cannot reason about it anymore.
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
/*
void SimpleErrorChecker::reportLeaks(ArrayRef<SymbolRef> LeakedStreams,
                                      CheckerContext &C,
                                      ExplodedNode *ErrNode) const {
  // Attach bug reports to the leak node.
  // TODO: Identify the leaked file descriptor.
  for (SymbolRef LeakedStream : LeakedStreams) {
    auto R = std::make_unique<PathSensitiveBugReport>(
        *LeakBugType, "Opened file is never closed; potential resource leak",
        ErrNode);
    R->markInteresting(LeakedStream);
    C.emitReport(std::move(R));
  }
}
*/
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
