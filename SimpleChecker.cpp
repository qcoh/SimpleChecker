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

// Rule A3-3-2 (required, implementation, automated)
// Non-POD type objects with static storage duration shall not be used.
class SimpleChecker : public Checker<check::ASTDecl<VarDecl>>
{
private:
	std::unique_ptr<BugType> m_bugType{
	    std::make_unique<BugType>(
		this,
		"Non-POD type objects with static storage duration shall not be used.",
		"Autosar required")};

public:
	void checkASTDecl(const VarDecl *varDecl, AnalysisManager &analysisManager, BugReporter &bugReporter) const
	{
		if (!varDecl)
		{
			return;
		}

		const bool isConstexpr = varDecl->isConstexpr();
		if (isConstexpr)
		{
			return;
		}

		const bool hasStaticStorageDuration = varDecl->isStaticLocal() || varDecl->isStaticDataMember() || varDecl->hasGlobalStorage();
		ASTContext &astContext = varDecl->getASTContext();
		const bool isPOD = varDecl->getType().isPODType(astContext);

		if (hasStaticStorageDuration && !isPOD)
		{
			PathDiagnosticLocation pathDiagnosticLocation =
			    PathDiagnosticLocation::create(varDecl, bugReporter.getSourceManager());

			bugReporter.emitReport(
			    std::make_unique<BugReport>(
				*m_bugType,
				m_bugType->getName(),
				pathDiagnosticLocation));
		}
	}
};

} // namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry)
{
	registry.addChecker<SimpleChecker>(
	    "autosar.A3-3-2",
	    "Non-POD type objects with static storage duration shall not be used.");
}

extern "C" const char clang_analyzerAPIVersionString[] = CLANG_ANALYZER_API_VERSION_STRING;
