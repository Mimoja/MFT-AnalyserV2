package main

import (
	"encoding/json"
	"github.com/Mimoja/MFT-Common"
	"github.com/Mimoja/MFT_AnalyserV2"
)

var Bundle MFTCommon.AppBundle

func handleResult() {

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
		}

		result := MFT_AnalyserV2.Analyse(file)
		handleResult(result)
		return nil
	})
	Bundle.Log.Info("Starting up!")
	select {}
}
