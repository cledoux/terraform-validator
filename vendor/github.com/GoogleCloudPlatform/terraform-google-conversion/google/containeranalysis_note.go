// ----------------------------------------------------------------------------
//
//     ***     AUTO GENERATED CODE    ***    AUTO GENERATED CODE     ***
//
// ----------------------------------------------------------------------------
//
//     This file is automatically generated by Magic Modules and manual
//     changes will be clobbered when the file is regenerated.
//
//     Please read more about how to change this file in
//     .github/CONTRIBUTING.md.
//
// ----------------------------------------------------------------------------

package google

import "reflect"

func GetContainerAnalysisNoteCaiObject(d TerraformResourceData, config *Config) (Asset, error) {
	name, err := assetName(d, config, "//containeranalysis.googleapis.com/projects/{{project}}/notes/{{name}}")
	if err != nil {
		return Asset{}, err
	}
	if obj, err := GetContainerAnalysisNoteApiObject(d, config); err == nil {
		return Asset{
			Name: name,
			Type: "containeranalysis.googleapis.com/Note",
			Resource: &AssetResource{
				Version:              "v1",
				DiscoveryDocumentURI: "https://www.googleapis.com/discovery/v1/apis/containeranalysis/v1/rest",
				DiscoveryName:        "Note",
				Data:                 obj,
			},
		}, nil
	} else {
		return Asset{}, err
	}
}

func GetContainerAnalysisNoteApiObject(d TerraformResourceData, config *Config) (map[string]interface{}, error) {
	obj := make(map[string]interface{})
	nameProp, err := expandContainerAnalysisNoteName(d.Get("name"), d, config)
	if err != nil {
		return nil, err
	} else if v, ok := d.GetOkExists("name"); !isEmptyValue(reflect.ValueOf(nameProp)) && (ok || !reflect.DeepEqual(v, nameProp)) {
		obj["name"] = nameProp
	}
	attestationAuthorityProp, err := expandContainerAnalysisNoteAttestationAuthority(d.Get("attestation_authority"), d, config)
	if err != nil {
		return nil, err
	} else if v, ok := d.GetOkExists("attestation_authority"); !isEmptyValue(reflect.ValueOf(attestationAuthorityProp)) && (ok || !reflect.DeepEqual(v, attestationAuthorityProp)) {
		obj["attestationAuthority"] = attestationAuthorityProp
	}

	return resourceContainerAnalysisNoteEncoder(d, config, obj)
}

func resourceContainerAnalysisNoteEncoder(d TerraformResourceData, meta interface{}, obj map[string]interface{}) (map[string]interface{}, error) {
	// Field was renamed in GA API
	obj["attestation"] = obj["attestationAuthority"]
	delete(obj, "attestationAuthority")

	return obj, nil
}

func expandContainerAnalysisNoteName(v interface{}, d TerraformResourceData, config *Config) (interface{}, error) {
	return v, nil
}

func expandContainerAnalysisNoteAttestationAuthority(v interface{}, d TerraformResourceData, config *Config) (interface{}, error) {
	l := v.([]interface{})
	if len(l) == 0 || l[0] == nil {
		return nil, nil
	}
	raw := l[0]
	original := raw.(map[string]interface{})
	transformed := make(map[string]interface{})

	transformedHint, err := expandContainerAnalysisNoteAttestationAuthorityHint(original["hint"], d, config)
	if err != nil {
		return nil, err
	} else if val := reflect.ValueOf(transformedHint); val.IsValid() && !isEmptyValue(val) {
		transformed["hint"] = transformedHint
	}

	return transformed, nil
}

func expandContainerAnalysisNoteAttestationAuthorityHint(v interface{}, d TerraformResourceData, config *Config) (interface{}, error) {
	l := v.([]interface{})
	if len(l) == 0 || l[0] == nil {
		return nil, nil
	}
	raw := l[0]
	original := raw.(map[string]interface{})
	transformed := make(map[string]interface{})

	transformedHumanReadableName, err := expandContainerAnalysisNoteAttestationAuthorityHintHumanReadableName(original["human_readable_name"], d, config)
	if err != nil {
		return nil, err
	} else if val := reflect.ValueOf(transformedHumanReadableName); val.IsValid() && !isEmptyValue(val) {
		transformed["humanReadableName"] = transformedHumanReadableName
	}

	return transformed, nil
}

func expandContainerAnalysisNoteAttestationAuthorityHintHumanReadableName(v interface{}, d TerraformResourceData, config *Config) (interface{}, error) {
	return v, nil
}
