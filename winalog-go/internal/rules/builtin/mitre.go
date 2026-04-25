package builtin

import (
	"github.com/kkkdddd-start/winalog-go/pkg/mitre"
)

func GetMITRETechnique(id string) (*mitre.ATTACKTechnique, error) {
	return mitre.GetTechnique(id)
}

func GetMITRETactic(id string) (*mitre.ATTACKTactic, error) {
	return mitre.GetTactic(id)
}

func GetTechniquesByTactic(tacticName string) []*mitre.ATTACKTechnique {
	return mitre.GetTechniquesByTactic(tacticName)
}

func GetTechniqueByEventID(eventID int32) []*mitre.ATTACKTechnique {
	return mitre.GetTechniqueByEventID(eventID)
}

func GetTacticByTechnique(techniqueID string) string {
	return mitre.GetTacticByTechnique(techniqueID)
}

func GetMITREMappingsForEvent(eventID int32) *mitre.MITREMapping {
	return mitre.GetMITREMappingsForEvent(eventID)
}

func GenerateMITREReport(eventMappings map[int32]int) *mitre.MITREReport {
	return mitre.GenerateMITREReport(eventMappings)
}

func ValidateTechniqueID(id string) bool {
	return mitre.ValidateTechniqueID(id)
}

func ValidateTacticID(id string) bool {
	return mitre.ValidateTacticID(id)
}
