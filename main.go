package main

import (
	"encoding/json"
	"fmt"
	"github.com/fadhilthomas/go-code-scanning-reporter/config"
	"github.com/fadhilthomas/go-code-scanning-reporter/model"
	"github.com/jomei/notionapi"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/rs/zerolog/pkgerrors"
	"go.uber.org/ratelimit"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
)

var (
	notionDatabase                      *notionapi.Client
	summaryReportStatus                 model.SummaryReportStatus
	scanSecretReport                    model.ScanSecret
	scanDependencyGoReport              model.ScanDependencyGo
	scanDependencyJsReport              model.ScanDependencyJs
	scanDependencyPhpReport             model.ScanDependencyPhp
	scanSecurityStaticCodeCodeQlReport  model.ScanSecurityStaticCodeCodeQl
	scanSecurityStaticCodeSemgrepReport model.ScanSecurityStaticCodeSemgrep
)

func main() {
	config.Set(config.LOG_LEVEL, "info")
	if config.GetStr(config.LOG_LEVEL) == "debug" {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	} else {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}
	zerolog.ErrorStackMarshaler = pkgerrors.MarshalStack

	repositoryName := config.GetStr(config.REPOSITORY_NAME)
	repositoryPullRequest := config.GetStr(config.REPOSITORY_PULL_REQUEST)
	scanType := config.GetStr(config.SCAN_TYPE)
	slackToken := config.GetStr(config.SLACK_TOKEN)
	rl := ratelimit.New(1)

	notionDatabase = model.OpenNotionDB()
	rl.Take()
	// find all open entries in repository
	notionQueryStatusResult, err := model.QueryNotionVulnerabilityStatus(notionDatabase, repositoryName, "open")
	if err != nil {
		log.Error().Stack().Err(errors.New(err.Error())).Msg("")
		return
	}
	// set status to close for all entries in repository
	for _, notionPage := range notionQueryStatusResult {
		rl.Take()
		_, err = model.UpdateNotionVulnerabilityStatus(notionDatabase, notionPage.ID.String(), "close")
		if err != nil {
			log.Error().Stack().Err(errors.New(err.Error())).Msg("")
			return
		}
		summaryReportStatus.Close++
	}

	fileReport, err := os.Open(config.GetStr(config.FILE_LOCATION))
	if err != nil {
		log.Error().Stack().Err(errors.New(err.Error())).Msg("")
		return
	}

	byteValue, _ := ioutil.ReadAll(fileReport)
	var vulnerabilityList []model.Vulnerability
	switch {
	case scanType == "scan-secret":
		err = json.Unmarshal(byteValue, &scanSecretReport)
		if err != nil {
			log.Error().Stack().Err(errors.New(err.Error())).Msg("")
			return
		}
		for _, scanSecret := range scanSecretReport {
			vulnerability := model.Vulnerability{}
			vulnerability.Name = scanSecret.Rule
			vulnerability.Path = scanSecret.File
			vulnerability.Detail = float64(scanSecret.LineNumber)
			vulnerabilityList = append(vulnerabilityList, vulnerability)
		}
	case scanType == "scan-dependency-go":
		err = json.Unmarshal(byteValue, &scanDependencyGoReport)
		if err != nil {
			log.Error().Stack().Err(errors.New(err.Error())).Msg("")
			return
		}
		for _, scanDependencyGo := range scanDependencyGoReport.Vulnerable {
			for _, scanDependencyGoDetail := range scanDependencyGo.Vulnerabilities {
				vulnerability := model.Vulnerability{}
				vulnerability.Name = scanDependencyGoDetail.Title
				vulnerability.Path = scanDependencyGo.Coordinates
				vulnerability.Detail, _ = strconv.ParseFloat(scanDependencyGoDetail.CvssScore, 64)
				vulnerabilityList = append(vulnerabilityList, vulnerability)
			}
		}
	case scanType == "scan-dependency-js":
		err = json.Unmarshal(byteValue, &scanDependencyJsReport)
		if err != nil {
			log.Error().Stack().Err(errors.New(err.Error())).Msg("")
			return
		}
		for _, scanDependencyJs := range scanDependencyJsReport {
			for _, scanDependencyJsDetail := range scanDependencyJs.Vulnerabilities {
				vulnerability := model.Vulnerability{}
				vulnerability.Name = scanDependencyJsDetail.Title
				vulnerability.Path = scanDependencyJs.Coordinates
				vulnerability.Detail = scanDependencyJsDetail.CvssScore
				vulnerabilityList = append(vulnerabilityList, vulnerability)
			}
		}
	case scanType == "scan-dependency-php":
		err = json.Unmarshal(byteValue, &scanDependencyPhpReport)
		if err != nil {
			log.Error().Stack().Err(errors.New(err.Error())).Msg("")
			return
		}
		for _, scanDependencyPhp := range scanDependencyPhpReport {
			for _, scanDependencyPhpDetail := range scanDependencyPhp.Vulnerabilities {
				vulnerability := model.Vulnerability{}
				vulnerability.Name = scanDependencyPhpDetail.Title
				vulnerability.Path = scanDependencyPhp.Coordinates
				vulnerability.Detail = scanDependencyPhpDetail.CvssScore
				vulnerabilityList = append(vulnerabilityList, vulnerability)
			}
		}
	case scanType == "scan-security-static-code-codeql":
		err = json.Unmarshal(byteValue, &scanSecurityStaticCodeCodeQlReport)
		if err != nil {
			log.Error().Stack().Err(errors.New(err.Error())).Msg("")
			return
		}
		for _, scanSecurityStaticCodeCodeQl := range scanSecurityStaticCodeCodeQlReport.Runs {
			for _, scanSecurityStaticCodeCodeQlDetail := range scanSecurityStaticCodeCodeQl.Results {
				vulnerability := model.Vulnerability{}
				vulnerability.Name = scanSecurityStaticCodeCodeQlDetail.RuleID
				vulnerability.Path = scanSecurityStaticCodeCodeQlDetail.Locations[0].PhysicalLocation.ArtifactLocation.URI
				vulnerability.Detail = float64(scanSecurityStaticCodeCodeQlDetail.Locations[0].PhysicalLocation.Region.StartLine)
				if vulnerability.Name != "go/hardcoded-credentials" {
					vulnerabilityList = append(vulnerabilityList, vulnerability)
				}
			}
		}
	case scanType == "scan-security-static-code-semgrep":
		err = json.Unmarshal(byteValue, &scanSecurityStaticCodeSemgrepReport)
		if err != nil {
			log.Error().Stack().Err(errors.New(err.Error())).Msg("")
			return
		}
		for _, scanSecurityStaticCodeSemgrep := range scanSecurityStaticCodeSemgrepReport {
			vulnerability := model.Vulnerability{}
			vulnerability.Name = scanSecurityStaticCodeSemgrep.CheckID
			vulnerability.Path = scanSecurityStaticCodeSemgrep.Path
			vulnerability.Detail = float64(scanSecurityStaticCodeSemgrep.Line)
			if scanSecurityStaticCodeSemgrep.Metadata.Category == "security" {
				vulnerabilityList = append(vulnerabilityList, vulnerability)
			}
		}
	}

	// loop vulnerability list
	for _, vulnerability := range vulnerabilityList {
		rl.Take()
		// search vuln in notion
		notionQueryNameResult, err := model.QueryNotionVulnerabilityName(notionDatabase, scanType, repositoryName, vulnerability.Name, vulnerability.Path, vulnerability.Detail)
		if err != nil {
			log.Error().Stack().Err(errors.New(err.Error())).Msg("")
			return
		}

		// if no result, insert vulnerability to notion. else update vulnerability status
		if len(notionQueryNameResult) > 0 {
			for _, notionPage := range notionQueryNameResult {
				rl.Take()
				_, err = model.UpdateNotionVulnerabilityStatus(notionDatabase, string(notionPage.ID), "open")
				if err != nil {
					log.Error().Stack().Err(errors.New(err.Error())).Msg("")
					return
				}
				summaryReportStatus.Open++
				summaryReportStatus.Close--
			}
		} else {
			rl.Take()
			_, err = model.InsertNotionVulnerability(notionDatabase, scanType, repositoryName, repositoryPullRequest, vulnerability.Name, vulnerability.Path, vulnerability.Detail)
			if err != nil {
				log.Error().Stack().Err(errors.New(err.Error())).Msg("")
				return
			}
			summaryReportStatus.New++
			summaryReportStatus.Open++
		}
	}
	summaryReportStatus.RepositoryPullRequest = fmt.Sprintf("https://github.com/%s%s", repositoryName, strings.ReplaceAll(strings.ReplaceAll(repositoryPullRequest, "refs", ""), "/merge", ""))
	summaryReportStatus.ScanType = scanType

	if summaryReportStatus.New == 0 {
		return
	} else {
		var slackBlockList []model.SlackBlockBody
		slackBlockList = append(slackBlockList, model.CreateBlockSummary(summaryReportStatus))
		err = model.SendSlackNotification(slackToken, slackBlockList)
		if err != nil {
			log.Error().Stack().Err(errors.New(err.Error())).Msg("")
			return
		}
	}
}
