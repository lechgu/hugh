package cmd

import (
	"bytes"
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

var decryptParams struct {
	privateKeyFile string
}

var decryptCmd = cobra.Command{
	Use:   "decrypt",
	Short: "Decrypt the secret",
	RunE: func(cmd *cobra.Command, args []string) error {
		var reader io.Reader
		if len(args) == 0 {
			reader = os.Stdin
		}
		if len(args) >= 1 {
			f, err := os.Open(args[0])
			cobra.CheckErr(err)
			defer f.Close()
			reader = f
		}
		var err error
		buf := new(bytes.Buffer)
		_, err = buf.ReadFrom(reader)
		if err != nil {
			return err
		}
		data, err := base64.StdEncoding.DecodeString(string(buf.Bytes()))
		if err != nil {
			return err
		}

		var privateKeyFile string

		privateKeyFile = decryptParams.privateKeyFile
		if privateKeyFile == "" {
			privateKeyFile = viper.GetString("private-key")
			privateKeyFile, err = homedir.Expand(privateKeyFile)
			if err != nil {
				return err
			}
		}
		if privateKeyFile == "" {
			return errors.New("private-key must be passed as a parameter or set in the config file")
		}

		privKeyReader, err := os.Open(privateKeyFile)
		if err != nil {
			return err
		}
		defer privKeyReader.Close()

		plainText, err := crypto.Decrypt(bytes.NewReader(data), privKeyReader)
		if err != nil {
			return err
		}
		fmt.Println(string(plainText))
		return nil
	},
}

func init() {
	decryptCmd.Flags().StringVarP(&decryptParams.privateKeyFile, "private-key", "r", "", "private key file name")
	rootCmd.AddCommand(&decryptCmd)
}
