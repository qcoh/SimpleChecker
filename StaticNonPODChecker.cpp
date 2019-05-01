#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/CheckerRegistry.h"
#include "clang/AST/Decl.h"

using namespace clang;
using namespace ento;

namespace
{

// Check for Autosar rule A3-3-2:
//
// Rule A3-3-2 (required, implementation, automated)
// Non-POD type objects with static storage duration shall not be used.
//
// Checks every variable declartion whether it has static storage duration
// and whether its type is non-POD.
class StaticNonPODChecker : public Checker<check::ASTDecl<VarDecl>>
{
      private:
	std::unique_ptr<BugType> m_staticNonPODBugType;

      public:
	StaticNonPODChecker() : m_staticNonPODBugType{std::make_unique<BugType>(this, "Declared non-POD variable with static storage duration", "AUTOSAR ERROR")}
	{
	}

	void checkASTDecl(const VarDecl *varDecl, AnalysisManager &analysisManager, BugReporter &bugReporter) const
	{
		if (!varDecl)
		{
			return;
		}

		const bool hasStaticStorageDuration = varDecl->isStaticLocal() || varDecl->isStaticDataMember();

		ASTContext &astContext = varDecl->getASTContext();
		const bool isPOD = varDecl->getType().isPODType(astContext);

		if (hasStaticStorageDuration && !isPOD)
		{
			PathDiagnosticLocation pathDiagnosticLocation =
			    PathDiagnosticLocation::create(varDecl, bugReporter.getSourceManager());

			bugReporter.EmitBasicReport(
			    varDecl,
			    this,
			    "A3-3-2",
			    "Required (AUTOSAR)",
			    "Non-POD type objects with static storage duration shall not be used.",
			    pathDiagnosticLocation);
		}
	}
};

} // namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry)
{
	registry.addChecker<StaticNonPODChecker>(
	    "autosar.A3-3-2",
	    "Non-POD type objects with static storage duration shall not be used.");
}

extern "C" const char clang_analyzerAPIVersionString[] = CLANG_ANALYZER_API_VERSION_STRING;
