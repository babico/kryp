package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	cfgFile        string
	algorithm      string
	passphrase     string
	keyFile        string
	kdfMethod      string
	uuidRename     bool
	embedMetadata  bool
	keepPath       bool
	ageRecipient   string
	sourceFiles    []string
	filesFrom      string
	seedFile       string
	extractPublic  bool
	compatible     bool
	outputDir      string
	decryptDir     string
	selectedFiles  []string
	keyFormat      string
	hashAlgorithm  string
	argon2Time     uint32
	argon2Memory   uint32
	argon2Threads  uint8
	scryptN        uint32
	scryptR        uint32
	scryptP        uint32
	pbkdf2Iter     uint32
)

var Version = "1.1.1"

func main() {
	rootCmd := &cobra.Command{
		Use:   "kryp",
		Short: "Encrypt/decrypt data for secure cloud storage",
		Long:  `Kryp — A powerful encryption tool for cloud storage with multiple algorithms and UUID renaming.`,
	}

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file path")

	rootCmd.AddCommand(encryptCmd())
	rootCmd.AddCommand(decryptCmd())
	rootCmd.AddCommand(listCmd())
	rootCmd.AddCommand(algorithmsCmd())
	rootCmd.AddCommand(genkeyCmd())
	rootCmd.AddCommand(initCmd())
	rootCmd.AddCommand(versionCmd())
	rootCmd.AddCommand(inspectCmd())
	rootCmd.AddCommand(hashCmd())
	rootCmd.AddCommand(infoCmd())

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
