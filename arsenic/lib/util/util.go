package util

import (
	"bufio"
	"fmt"

	// "io/ioutil"
	"log"
	"os"
	"os/exec"
	"sort"

	// "strings"
	"syscall"
	"time"

	"github.com/spf13/viper"
)

type Mappable interface {
	ToMap() map[string]interface{}
}

type ScriptConfig struct {
	Script  string
	Order   int
	Enabled bool
}

func NewScriptConfig(script string, order int, enabled bool) ScriptConfig {
	return ScriptConfig{
		Script:  script,
		Order:   order,
		Enabled: enabled,
	}
}

func (c ScriptConfig) ToMap() map[string]interface{} {
	mapping := make(map[string]interface{})
	mapping["script"] = c.Script
	mapping["order"] = c.Order
	mapping["enabled"] = c.Enabled
	return mapping
}

func GetScripts(phase string) []ScriptConfig {
	scripts := map[string]map[string]ScriptConfig{}
	viper.UnmarshalKey("scripts", &scripts)
	phaseScripts := []ScriptConfig{}
	for _, scriptConfig := range scripts[phase] {
		phaseScripts = append(phaseScripts, scriptConfig)
	}

	sort.SliceStable(phaseScripts, func(i, j int) bool {
		return phaseScripts[i].Order < phaseScripts[j].Order
	})
	return phaseScripts
}

func ExecScript(scriptPath string, args []string) int {
	cmd := exec.Command(scriptPath, args...)

	stderr, _ := cmd.StderrPipe()
	stdout, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		log.Fatalf("cmd.Start: %v", err)
	}

	scannerEr := bufio.NewScanner(stderr)
	scannerEr.Split(bufio.ScanLines)
	go func() {
		for scannerEr.Scan() {
			m := scannerEr.Text()
			fmt.Println(m)
		}
	}()

	scanner := bufio.NewScanner(stdout)
	scanner.Split(bufio.ScanLines)
	go func() {
		for scanner.Scan() {
			m := scanner.Text()
			fmt.Println(m)
		}
	}()

	exitStatus := 0
	if err := cmd.Wait(); err != nil {
		if exiterr, ok := err.(*exec.ExitError); ok {
			if status, ok := exiterr.Sys().(syscall.WaitStatus); ok {
				exitStatus = status.ExitStatus()
			}
		} else {
			log.Fatalf("cmd.Wait: %v", err)
		}
	}
	return exitStatus
}

func ExecutePhaseScripts(phase string) {
	scripts := GetScripts(phase)
	for len(scripts) > 0 {
		currentScript := scripts[0]
		if currentScript.Enabled {
			fmt.Printf("Running %s\n", currentScript.Script)
			args := []string{}
			if ExecScript(currentScript.Script, args) == 0 {
				scripts = scripts[1:]
			} else {
				fmt.Printf("Script failed, gonna retry: %s\n", currentScript.Script)
				time.Sleep(10 * time.Second)
			}
		} else {
			// not enabled.. remove
			scripts = scripts[1:]
		}
	}
}

func ReadLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}
