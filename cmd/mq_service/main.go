package main

import (
	"encoding/json"
	"github.com/Mimoja/MFT-Common"
	"github.com/Mimoja/MFT-AnalyserV2"
	"io/ioutil"
)

var Bundle MFTCommon.AppBundle

func handleResult(result MFT_AnalyserV2.Result) {

}

func main() {
	Bundle = MFTCommon.Init("AnalyserV2")

	MFT_AnalyserV2.SetupYara()

	Bundle.MessageQueue.FlashImagesQueue.RegisterCallback("AnalyserV2", func(payload string) error {

		Bundle.Log.WithField("payload", payload).Debug("Got new Message!")
		var file MFTCommon.FlashImage
		err := json.Unmarshal([]byte(payload), &file)
		if err != nil {
			Bundle.Log.WithError(err).Error("Could not unmarshall json: %v", err)
			return err;
		}

		binary_file,err := Bundle.Storage.GetFile(file.ID.GetID())
		if err != nil {
			Bundle.Log.WithError(err).Error("Could not load file: %v", err)
			return err;
		}

		defer binary_file.Close();
		all, err := ioutil.ReadAll(binary_file)
		if err != nil {
			Bundle.Log.WithError(err).Error("Could not read file: %v", err)
			return err;
		}

		result, err := MFT_AnalyserV2.Analyse(all)
		if err != nil {
			Bundle.Log.WithError(err).Error("Could analyse file: %v", err)
			return err;
		}

		handleResult(result)
		return nil
	})
	Bundle.Log.Info("Starting up!")
	select {}
}
