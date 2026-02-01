package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"go.yaml.in/yaml/v4"
)

var (
	buildVersion string
	buildCommit  string
	buildDate    string
)

const (
	rulesDir    = "/etc/falco/rules.d"
	stableRules = "/etc/falco/falco_rules.yaml"
	envRules    = "FALCO_VALIDATOR_RULES"
	envStable   = "FALCO_VALIDATOR_STABLE"
)

type PluginDependency struct {
	Name    string `yaml:"name"`
	Version string `yaml:"version"`
}

type RulesFile struct {
	RequiredPluginVersions []PluginDependency `yaml:"required_plugin_versions"`
}

type FalcoValidator struct {
	useStableRules bool
}

func NewFalcoValidator(useStableRules bool) *FalcoValidator {
	return &FalcoValidator{
		useStableRules: useStableRules,
	}
}

func (f *FalcoValidator) ParseRulesFile(path string) ([]PluginDependency, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304 - file path is controlled by caller
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", path, err)
	}

	var rulesFile []RulesFile
	if err := yaml.Unmarshal(data, &rulesFile); err != nil {
		return nil, fmt.Errorf("failed to unmarshal YAML: %w", err)
	}

	var deps []PluginDependency
	for _, rf := range rulesFile {
		deps = append(deps, rf.RequiredPluginVersions...)
	}

	return deps, nil
}

func (f *FalcoValidator) DeduplicatePlugins(deps []PluginDependency) []PluginDependency {
	seen := make(map[string]bool)
	var result []PluginDependency

	for _, dep := range deps {
		if !seen[dep.Name] {
			seen[dep.Name] = true
			result = append(result, dep)
		}
	}

	return result
}

func (f *FalcoValidator) ExtractPluginDependencies(paths []string) ([]PluginDependency, error) {
	var allDeps []PluginDependency
	for _, path := range paths {
		deps, err := f.ParseRulesFile(path)
		if err != nil {
			return nil, fmt.Errorf("error parsing %s: %w", path, err)
		}
		allDeps = append(allDeps, deps...)
	}

	allDeps = f.DeduplicatePlugins(allDeps)

	return allDeps, nil
}

func (f *FalcoValidator) InstallArtifact(ref string) error {
	args := []string{
		"artifact", "install", ref,
		"--rulesfiles-dir=" + rulesDir,
	}

	//nolint:gosec // G204 - args are safe and constructed within function
	cmd := exec.Command("falcoctl", args...)
	cmd.Stdout = nil
	cmd.Stderr = nil

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to install artifact %s: %w", ref, err)
	}

	return nil
}

func (f *FalcoValidator) ProcessInput(inputs []string) ([]string, error) {
	var rulePaths []string

	if f.useStableRules {
		rulePaths = append(rulePaths, stableRules)
	}

	for _, input := range inputs {
		if strings.Contains(input, "/") || strings.HasSuffix(input, ".yaml") || strings.HasSuffix(input, ".yml") {
			rulePaths = append(rulePaths, input)
		} else if err := f.InstallArtifact(input); err != nil {
			return nil, fmt.Errorf("failed to install artifact %s: %w", input, err)
		}
	}

	dir, err := os.ReadDir(rulesDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read dir %s: %w", rulesDir, err)
	}

	for _, de := range dir {
		if strings.HasSuffix(de.Name(), ".yaml") {
			rulePaths = append(rulePaths, filepath.Join(rulesDir, de.Name()))
		}
	}

	slices.Sort(rulePaths)
	return rulePaths, nil
}

func (f *FalcoValidator) CombineRulesFiles(inputPaths []string, outputPath string) error {
	outFile, err := os.Create(outputPath) //nolint:gosec // G304 - output path is controlled by caller
	if err != nil {
		return fmt.Errorf("failed to create output file %s: %w", outputPath, err)
	}
	defer outFile.Close()

	for _, inputPath := range inputPaths {
		fmt.Printf("appending %s\n", inputPath)
		if err := f.appendFile(outFile, inputPath); err != nil {
			return fmt.Errorf("failed to append file %s: %w", inputPath, err)
		}
	}

	return nil
}

func (f *FalcoValidator) appendFile(outFile *os.File, inputPath string) error {
	inFile, err := os.Open(inputPath) //nolint:gosec // G304 - input path is controlled by caller
	if err != nil {
		return err
	}
	defer inFile.Close()

	if _, err := io.Copy(outFile, inFile); err != nil {
		return err
	}

	return nil
}

func (f *FalcoValidator) WriteConfig(path string, plugins []PluginDependency) error {
	type FalcoConfigPlugin struct {
		Name        string `yaml:"name"`
		LibraryPath string `yaml:"library_path"`
	}
	config := struct {
		Plugins []FalcoConfigPlugin `yaml:"plugins"`
	}{
		Plugins: []FalcoConfigPlugin{},
	}
	for _, p := range plugins {
		config.Plugins = append(config.Plugins, FalcoConfigPlugin{Name: p.Name, LibraryPath: fmt.Sprintf("lib%s.so", p.Name)})
	}
	configYAML, err := yaml.Marshal(config)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, configYAML, 0644); err != nil { //nolint:gosec // G306 - 0644 is appropriate for config files
		return fmt.Errorf("failed to write config to %s: %w", path, err)
	}
	return nil
}

func (f *FalcoValidator) ValidateWithOutput(configPath, rulesPath string) (string, error) {
	args := []string{
		"-c", configPath,
		"-V", rulesPath,
	}

	//nolint:gosec // G204 - args are safe and constructed within function
	cmd := exec.Command("falco", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return string(output), fmt.Errorf("validation failed: %w", err)
	}

	return string(output), nil
}

func (f *FalcoValidator) Run(args []string) error {
	fmt.Println("Processing inputs...")
	rulePaths, err := f.ProcessInput(args)
	if err != nil {
		return err
	}

	fmt.Printf("Found %d rules files\n", len(rulePaths))

	fmt.Println("Extracting plugin dependencies...")
	plugins, err := f.ExtractPluginDependencies(rulePaths)
	if err != nil {
		return fmt.Errorf("failed to extract plugin dependencies: %w", err)
	}

	fmt.Printf("Found %d required plugins\n", len(plugins))
	for _, p := range plugins {
		fmt.Printf("  - %s@%s\n", p.Name, p.Version)
	}

	configPath := "/tmp/falco-validator-config.yaml"
	fmt.Printf("Generating falco config at %s\n", configPath)
	if err := f.WriteConfig(configPath, plugins); err != nil {
		return fmt.Errorf("failed to generate config: %w", err)
	}
	defer os.Remove(configPath)

	rulesPath := "/tmp/falco-validator-rules.yaml"
	fmt.Printf("Combining rules files into %s\n", rulesPath)
	if err := f.CombineRulesFiles(rulePaths, rulesPath); err != nil {
		return fmt.Errorf("failed to combine rules files: %w", err)
	}
	defer os.Remove(rulesPath)

	fmt.Println("Running falco validation...")
	output, err := f.ValidateWithOutput(configPath, rulesPath)
	if output != "" {
		fmt.Println(output)
	}

	return err
}

func main() {
	var (
		useStableRules bool
		version        bool
	)

	flag.BoolVar(&useStableRules, "stable", false, "Inject Falco stable ruleset")
	flag.BoolVar(&version, "version", false, "Print version information")
	flag.Parse()

	if version {
		fmt.Printf("Version: %s\nCommit:  %s\nDate:    %s\n", buildVersion, buildCommit, buildDate)
		os.Exit(0)
	}

	cliArgs := flag.Args()

	envRulesValue := os.Getenv(envRules)
	envStableValue := os.Getenv(envStable)

	var allArgs []string

	if envRulesValue != "" {
		allArgs = append(allArgs, strings.Fields(envRulesValue)...)
	}

	allArgs = append(allArgs, cliArgs...)

	if envStableValue != "" && !useStableRules {
		switch strings.ToLower(envStableValue) {
		case "1", "true", "yes", "on":
			useStableRules = true
		}
	}

	if len(allArgs) == 0 {
		fmt.Fprintln(os.Stderr, "usage: falco-validator [flags] <artifact|file> [artifact|file ...]")
		os.Exit(1)
	}

	validator := NewFalcoValidator(useStableRules)
	if err := validator.Run(allArgs); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	fmt.Println("Validation successful!")
}
