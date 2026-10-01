package projectlist

import (
	"encoding/json"
	"fmt"
	"unicode"
	"unicode/utf8"
)

const Version = 1
const MaxProjects = 256

type Project struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type Result struct {
	Version  int       `json:"version"`
	Projects []Project `json:"projects"`
}

func FromBWS(data []byte) (Result, error) {
	var source []struct {
		Object string `json:"object"`
		ID     string `json:"id"`
		Name   string `json:"name"`
	}
	if err := json.Unmarshal(data, &source); err != nil || source == nil {
		return Result{}, fmt.Errorf("invalid BWS project list")
	}
	result := Result{Version: Version, Projects: make([]Project, 0, len(source))}
	for _, item := range source {
		if item.Object != "project" {
			return Result{}, fmt.Errorf("invalid BWS project list")
		}
		result.Projects = append(result.Projects, Project{ID: item.ID, Name: item.Name})
	}
	if err := result.Validate(); err != nil {
		return Result{}, fmt.Errorf("invalid BWS project list")
	}
	return result, nil
}

func (r Result) Validate() error {
	if r.Version != Version || r.Projects == nil || len(r.Projects) > MaxProjects {
		return fmt.Errorf("invalid project list envelope")
	}
	seen := make(map[string]struct{}, len(r.Projects))
	for _, item := range r.Projects {
		if !safeText(item.ID, 128) || !safeText(item.Name, 256) {
			return fmt.Errorf("invalid project identifier or name")
		}
		if _, ok := seen[item.ID]; ok {
			return fmt.Errorf("duplicate project ID")
		}
		seen[item.ID] = struct{}{}
	}
	return nil
}

func safeText(s string, limit int) bool {
	if s == "" || len(s) > limit || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}
