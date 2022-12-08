package rules

import "github.com/zricethezav/gitleaks/v8/config"

func DotnetAppSettings() *config.Rule {
	r := config.Rule{
		Description: "Dotnet Appsettings ConnectionStrings",
		RuleID:      "dotnet-appsettings-connection-strings",
		Regex:       generateUniqueTokenRegex("(?i)((key|api|token|secret|password)[a-z0-9_ .\\-,]{0,25})['\\\"]?(=|>|:=|\\|\\|:|<=|=>|:).{0,5}['\\\"]([0-9a-zA-Z!\"#$%&'()*+,-.\\/:;<=>?@[\\\\\\]^_`{|}~]{8,64})['\\\"]\n\n,"),
		Path:        generateUniqueTokenRegex("**/AppSettings*.json"),
	}

	tps := []string{`"ConnectionStrings": {
    		"BloggingDatabase": "Server=(localdb)\\mssqllocaldb;Database=EFGetStarted.ConsoleApp.NewDb;Trusted_Connection=True;"
  		},
`}
	return validate(r, tps, nil)
}
