package cmd

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/lechgu/hugh/internal/crypto"
	"github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var encryptParams struct {
	publicKeyFile string
}

var encryptCmd = cobra.Command{
	Use:   "encrypt",
	Short: "Encrypt the secret",
	RunE: func(cmd *cobra.Command, args []string) error {
		var plainTextReader io.Reader
		if len(args) == 0 {
			plainTextReader = os.Stdin
		}
		if len(args) >= 1 {
			f, err := os.Open(args[0])
			cobra.CheckErr(err)
			defer f.Close()
			plainTextReader = f
		}
		var publicKeyFile string
		var err error
		publicKeyFile = encryptParams.publicKeyFile
		if publicKeyFile == "" {
			publicKeyFile = viper.GetString("public-key")
			publicKeyFile, err = homedir.Expand(publicKeyFile)
			if err != nil {
				return err
			}
		}
		if publicKeyFile == "" {
			return errors.New("public-key must be passed as a parameter or set in the config file")
		}

		publicKeyReader, err := os.Open(publicKeyFile)
		if err != nil {
			return err
		}
		defer publicKeyReader.Close()
		cipherText, err := crypto.Encrypt(plainTextReader, publicKeyReader)
		if err != nil {
			return err
		}

		fmt.Println(string(base64.StdEncoding.EncodeToString(cipherText)))
		return nil
	},
}

func init() {
	encryptCmd.Flags().StringVarP(&encryptParams.publicKeyFile, "public-key", "p", "", "public key file name")
	rootCmd.AddCommand(&encryptCmd)
}
