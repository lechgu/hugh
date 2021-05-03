package cmd

import (
	"errors"
	"fmt"
	"strings"

	"github.com/sethvargo/go-password/password"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var generateParams struct {
	passwordLength   int
	characterClasses string
}

var generateCmd = cobra.Command{
	Use:   "generate",
	Short: "Generate a random password",
	RunE: func(cmd *cobra.Command, args []string) error {
		classes := generateParams.characterClasses
		if classes == "" {
			if viper.Get("character-classes") != nil {
				classes = viper.GetString("character-classes")
			}
		}
		if classes == "" {
			return errors.New("Undefined character classes")
		}
		digs := 0
		if strings.Contains(classes, "8") {
			digs = 1
		}
		symbols := 0
		if strings.Contains(classes, "#") {
			symbols = 1
		}
		noUpper := false
		if !strings.Contains(classes, "A") {
			noUpper = true
		}

		len := generateParams.passwordLength
		if len == 0 {
			if viper.Get("password-length") != nil {
				len = viper.GetInt("password-length")
			}
			if len <= 0 {
				len = 4
			}
		}

		if digs >= 1 {
			digs = len / 4
		}
		if symbols >= 1 {
			symbols = len / 4
		}
		pwd, err := password.Generate(len, digs, symbols, noUpper, false)
		cobra.CheckErr(err)
		fmt.Println(pwd)
		return nil
	},
}

func init() {
	generateCmd.Flags().IntVarP(&generateParams.passwordLength, "password-length", "l", 0, "password length")
	generateCmd.Flags().StringVarP(&generateParams.characterClasses, "character-classes", "c", "", "classes of allowed characters (aA8#)")
	rootCmd.AddCommand(&generateCmd)
}
