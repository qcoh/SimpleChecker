#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/CheckerRegistry.h"

#include <stdlib.h>
#include <iostream>

using namespace clang;
using namespace ento;

namespace
{

class FooChecker : public Checker<check::PreCall>
{
      private:
	std::unique_ptr<BugType> m_mallocBug;

      public:
	FooChecker() : m_mallocBug{std::make_unique<BugType>(this, "Used malloc", "Foo error")}
	{
		malloc(1);

		std::cout << "FOOCHECKER\n";
	}

	void checkPreCall(const CallEvent &call, CheckerContext &C) const
	{
		if (call.isGlobalCFunction("malloc"))
		{
			ExplodedNode *ErrNode = C.generateErrorNode();

			auto R = llvm::make_unique<BugReport>(*m_mallocBug, "Using malloc", ErrNode);
			R->addRange(call.getSourceRange());
			R->markInteresting(call.getArgSVal(0).getAsSymbol());
			C.emitReport(std::move(R));
		}

		// always a bug, default checker
		//int i = *(int*)NULL;
	}
};

} // namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry)
{
	registry.addChecker<FooChecker>("fuck.FooChecker", "does some shit");

	std::cout << "FOOCHECKER\n";
}

extern "C" const char clang_analyzerAPIVersionString[] = CLANG_ANALYZER_API_VERSION_STRING;
