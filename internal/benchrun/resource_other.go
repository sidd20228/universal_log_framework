//go:build !darwin && !linux

package benchrun

import "time"

type processResources struct{}

func readProcessResources() processResources { return processResources{} }

func resourceDelta(processResources, processResources, time.Duration) Resources { return Resources{} }

func hardwareInfo() (string, uint64) { return "unknown", 0 }
