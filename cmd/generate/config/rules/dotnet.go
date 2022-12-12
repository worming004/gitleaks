package rules

import (
	"github.com/zricethezav/gitleaks/v8/config"
	"regexp"
)

func DotnetAppSettingsPasswordValue() *config.Rule {
	r := config.Rule{
		Description: "Dotnet Appsettings ConnectionStrings",
		RuleID:      "dotnet-appsettings-connection-strings",
		Regex:       regexp.MustCompile(`[pP]assword=[^;":]`),
		Keywords: []string{"ConnectionStrings"},
	}

	tps := []string{`"ConnectionStrings = { BloggingDatabase": "Server=(localdb)\\mssqllocaldb;Database=EFGetStarted.ConsoleApp.NewDb;User=user;Password=pswd" }`}
	return validate(r, tps, nil)
}


func DotnetAppSettingsEsbPassword() *config.Rule {
	r := config.Rule{
		Description: "Dotnet Esb Password",
		RuleID:      "dotnet-esb-password",
		Regex:       regexp.MustCompile(`[pP]assword":\s*".+"`),
	}

	tps := []string{`"Password": "vqlu3"`}
	return validate(r, tps, nil)
}
