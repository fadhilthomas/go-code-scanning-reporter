package model

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
	"net/http"
	"time"
)

type SlackRequestBody struct {
	Title       string                `json:"title"`
	Text        string                `json:"text"`
	Attachments []SlackAttachmentBody `json:"attachments"`
	Blocks      []SlackBlockBody      `json:"blocks"`
}

type SlackAttachmentBody struct {
	Color  string           `json:"color"`
	Fields []SlackFieldBody `json:"fields"`
}

type SlackBlockBody struct {
	Type string              `json:"type"`
	Text SlackBlockFieldBody `json:"text"`
}

type SlackFieldBody struct {
	Title string `json:"title"`
	Value string `json:"value"`
	Short bool   `json:"short"`
}

type SlackBlockFieldBody struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

func CreateBlockSummary(status SummaryReportStatus) (block SlackBlockBody) {
	summaryField := SlackBlockFieldBody{
		Type: "mrkdwn",
		Text: fmt.Sprintf("> *Secure Code Scanning*, @here\n> *Scan Type:* `%s`\n> *Repository Pull Request:* `%s`\n```Status      Count\n-------------------\nClose         %d\nOpen          %d\nNew           %d\n-------------------\nTotal         %d```", status.ScanType, status.RepositoryPullRequest, status.Close, status.Open, status.New, status.Open+status.Close),
	}

	block = SlackBlockBody{
		Type: "section",
		Text: summaryField,
	}
	return block
}

func SendSlackNotification(webHookURL string, blockList []SlackBlockBody) error {
	slackMessage := SlackRequestBody{
		Title:  "Secure Code Scanning",
		Text:   "Secure Code Scanning",
		Blocks: blockList,
	}

	slackBody, err := json.Marshal(slackMessage)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, webHookURL, bytes.NewBuffer(slackBody))
	if err != nil {
		return err
	}

	req.Header.Add("Content-Type", "application/json")
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req) //nolint:bodyclose
	if err != nil {
		return err
	}

	buf := new(bytes.Buffer)
	_, err = buf.ReadFrom(resp.Body)
	if err != nil {
		return err
	}
	log.Debug().Str("file", "main").Msg(buf.String())
	if buf.String() != "ok" {
		return errors.New("non-ok response returned from slack")
	}
	return nil
}
