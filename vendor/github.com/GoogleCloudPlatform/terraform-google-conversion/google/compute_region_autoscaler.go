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

import (
	"fmt"
	"reflect"
)

func GetComputeRegionAutoscalerCaiObject(d TerraformResourceData, config *Config) (Asset, error) {
	name, err := assetName(d, config, "//compute.googleapis.com/projects/{{project}}/regions/{{region}}/autoscalers/{{name}}")
	if err != nil {
		return Asset{}, err
	}
	if obj, err := GetComputeRegionAutoscalerApiObject(d, config); err == nil {
		return Asset{
			Name: name,
			Type: "compute.googleapis.com/RegionAutoscaler",
			Resource: &AssetResource{
				Version:              "v1",
				DiscoveryDocumentURI: "https://www.googleapis.com/discovery/v1/apis/compute/v1/rest",
				DiscoveryName:        "RegionAutoscaler",
				Data:                 obj,
			},
		}, nil
	} else {
		return Asset{}, err
	}
}

func GetComputeRegionAutoscalerApiObject(d TerraformResourceData, config *Config) (map[string]interface{}, error) {
	obj := make(map[string]interface{})
	nameProp, err := expandComputeRegionAutoscalerName(d.Get("name"), d, config)
	if err != nil {
		return nil, err
	} else if v, ok := d.GetOkExists("name"); !isEmptyValue(reflect.ValueOf(nameProp)) && (ok || !reflect.DeepEqual(v, nameProp)) {
		obj["name"] = nameProp
	}
	descriptionProp, err := expandComputeRegionAutoscalerDescription(d.Get("description"), d, config)
	if err != nil {
		return nil, err
	} else if v, ok := d.GetOkExists("description"); !isEmptyValue(reflect.ValueOf(descriptionProp)) && (ok || !reflect.DeepEqual(v, descriptionProp)) {
		obj["description"] = descriptionProp
	}
	autoscalingPolicyProp, err := expandComputeRegionAutoscalerAutoscalingPolicy(d.Get("autoscaling_policy"), d, config)
	if err != nil {
		return nil, err
	} else if v, ok := d.GetOkExists("autoscaling_policy"); !isEmptyValue(reflect.ValueOf(autoscalingPolicyProp)) && (ok || !reflect.DeepEqual(v, autoscalingPolicyProp)) {
		obj["autoscalingPolicy"] = autoscalingPolicyProp
	}
	targetProp, err := expandComputeRegionAutoscalerTarget(d.Get("target"), d, config)
	if err != nil {
		return nil, err
	} else if v, ok := d.GetOkExists("target"); !isEmptyValue(reflect.ValueOf(targetProp)) && (ok || !reflect.DeepEqual(v, targetProp)) {
		obj["target"] = targetProp
	}
	regionProp, err := expandComputeRegionAutoscalerRegion(d.Get("region"), d, config)
	if err != nil {
		return nil, err
	} else if v, ok := d.GetOkExists("region"); !isEmptyValue(reflect.ValueOf(regionProp)) && (ok || !reflect.DeepEqual(v, regionProp)) {
		obj["region"] = regionProp
	}

	return obj, nil
}

func expandComputeRegionAutoscalerName(v interface{}, d TerraformResourceData, config *Config) (interface{}, error) {
	return v, nil
}

func expandComputeRegionAutoscalerDescription(v interface{}, d TerraformResourceData, config *Config) (interface{}, error) {
	return v, nil
}

func expandComputeRegionAutoscalerAutoscalingPolicy(v interface{}, d TerraformResourceData, config *Config) (interface{}, error) {
	l := v.([]interface{})
	if len(l) == 0 || l[0] == nil {
		return nil, nil
	}
	raw := l[0]
	original := raw.(map[string]interface{})
	transformed := make(map[string]interface{})

	transformedMinReplicas, err := expandComputeRegionAutoscalerAutoscalingPolicyMinReplicas(original["min_replicas"], d, config)
	if err != nil {
		return nil, err
	} else {
		transformed["minNumReplicas"] = transformedMinReplicas
	}

	transformedMaxReplicas, err := expandComputeRegionAutoscalerAutoscalingPolicyMaxReplicas(original["max_replicas"], d, config)
	if err != nil {
		return nil, err
	} else if val := reflect.ValueOf(transformedMaxReplicas); val.IsValid() && !isEmptyValue(val) {
		transformed["maxNumReplicas"] = transformedMaxReplicas
	}

	transformedCooldownPeriod, err := expandComputeRegionAutoscalerAutoscalingPolicyCooldownPeriod(original["cooldown_period"], d, config)
	if err != nil {
		return nil, err
	} else if val := reflect.ValueOf(transformedCooldownPeriod); val.IsValid() && !isEmptyValue(val) {
		transformed["coolDownPeriodSec"] = transformedCooldownPeriod
	}

	transformedCpuUtilization, err := expandComputeRegionAutoscalerAutoscalingPolicyCpuUtilization(original["cpu_utilization"], d, config)
	if err != nil {
		return nil, err
	} else if val := reflect.ValueOf(transformedCpuUtilization); val.IsValid() && !isEmptyValue(val) {
		transformed["cpuUtilization"] = transformedCpuUtilization
	}

	transformedMetric, err := expandComputeRegionAutoscalerAutoscalingPolicyMetric(original["metric"], d, config)
	if err != nil {
		return nil, err
	} else if val := reflect.ValueOf(transformedMetric); val.IsValid() && !isEmptyValue(val) {
		transformed["customMetricUtilizations"] = transformedMetric
	}

	transformedLoadBalancingUtilization, err := expandComputeRegionAutoscalerAutoscalingPolicyLoadBalancingUtilization(original["load_balancing_utilization"], d, config)
	if err != nil {
		return nil, err
	} else if val := reflect.ValueOf(transformedLoadBalancingUtilization); val.IsValid() && !isEmptyValue(val) {
		transformed["loadBalancingUtilization"] = transformedLoadBalancingUtilization
	}

	return transformed, nil
}

func expandComputeRegionAutoscalerAutoscalingPolicyMinReplicas(v interface{}, d TerraformResourceData, config *Config) (interface{}, error) {
	return v, nil
}

func expandComputeRegionAutoscalerAutoscalingPolicyMaxReplicas(v interface{}, d TerraformResourceData, config *Config) (interface{}, error) {
	return v, nil
}

func expandComputeRegionAutoscalerAutoscalingPolicyCooldownPeriod(v interface{}, d TerraformResourceData, config *Config) (interface{}, error) {
	return v, nil
}

func expandComputeRegionAutoscalerAutoscalingPolicyCpuUtilization(v interface{}, d TerraformResourceData, config *Config) (interface{}, error) {
	l := v.([]interface{})
	if len(l) == 0 || l[0] == nil {
		return nil, nil
	}
	raw := l[0]
	original := raw.(map[string]interface{})
	transformed := make(map[string]interface{})

	transformedTarget, err := expandComputeRegionAutoscalerAutoscalingPolicyCpuUtilizationTarget(original["target"], d, config)
	if err != nil {
		return nil, err
	} else if val := reflect.ValueOf(transformedTarget); val.IsValid() && !isEmptyValue(val) {
		transformed["utilizationTarget"] = transformedTarget
	}

	return transformed, nil
}

func expandComputeRegionAutoscalerAutoscalingPolicyCpuUtilizationTarget(v interface{}, d TerraformResourceData, config *Config) (interface{}, error) {
	return v, nil
}

func expandComputeRegionAutoscalerAutoscalingPolicyMetric(v interface{}, d TerraformResourceData, config *Config) (interface{}, error) {
	l := v.([]interface{})
	req := make([]interface{}, 0, len(l))
	for _, raw := range l {
		if raw == nil {
			continue
		}
		original := raw.(map[string]interface{})
		transformed := make(map[string]interface{})

		transformedName, err := expandComputeRegionAutoscalerAutoscalingPolicyMetricName(original["name"], d, config)
		if err != nil {
			return nil, err
		} else if val := reflect.ValueOf(transformedName); val.IsValid() && !isEmptyValue(val) {
			transformed["metric"] = transformedName
		}

		transformedTarget, err := expandComputeRegionAutoscalerAutoscalingPolicyMetricTarget(original["target"], d, config)
		if err != nil {
			return nil, err
		} else if val := reflect.ValueOf(transformedTarget); val.IsValid() && !isEmptyValue(val) {
			transformed["utilizationTarget"] = transformedTarget
		}

		transformedType, err := expandComputeRegionAutoscalerAutoscalingPolicyMetricType(original["type"], d, config)
		if err != nil {
			return nil, err
		} else if val := reflect.ValueOf(transformedType); val.IsValid() && !isEmptyValue(val) {
			transformed["utilizationTargetType"] = transformedType
		}

		req = append(req, transformed)
	}
	return req, nil
}

func expandComputeRegionAutoscalerAutoscalingPolicyMetricName(v interface{}, d TerraformResourceData, config *Config) (interface{}, error) {
	return v, nil
}

func expandComputeRegionAutoscalerAutoscalingPolicyMetricTarget(v interface{}, d TerraformResourceData, config *Config) (interface{}, error) {
	return v, nil
}

func expandComputeRegionAutoscalerAutoscalingPolicyMetricType(v interface{}, d TerraformResourceData, config *Config) (interface{}, error) {
	return v, nil
}

func expandComputeRegionAutoscalerAutoscalingPolicyLoadBalancingUtilization(v interface{}, d TerraformResourceData, config *Config) (interface{}, error) {
	l := v.([]interface{})
	if len(l) == 0 || l[0] == nil {
		return nil, nil
	}
	raw := l[0]
	original := raw.(map[string]interface{})
	transformed := make(map[string]interface{})

	transformedTarget, err := expandComputeRegionAutoscalerAutoscalingPolicyLoadBalancingUtilizationTarget(original["target"], d, config)
	if err != nil {
		return nil, err
	} else if val := reflect.ValueOf(transformedTarget); val.IsValid() && !isEmptyValue(val) {
		transformed["utilizationTarget"] = transformedTarget
	}

	return transformed, nil
}

func expandComputeRegionAutoscalerAutoscalingPolicyLoadBalancingUtilizationTarget(v interface{}, d TerraformResourceData, config *Config) (interface{}, error) {
	return v, nil
}

func expandComputeRegionAutoscalerTarget(v interface{}, d TerraformResourceData, config *Config) (interface{}, error) {
	return v, nil
}

func expandComputeRegionAutoscalerRegion(v interface{}, d TerraformResourceData, config *Config) (interface{}, error) {
	f, err := parseGlobalFieldValue("regions", v.(string), "project", d, config, true)
	if err != nil {
		return nil, fmt.Errorf("Invalid value for region: %s", err)
	}
	return f.RelativeLink(), nil
}
