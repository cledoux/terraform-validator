// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/GoogleCloudPlatform/terraform-validator/converters/google"
	"github.com/GoogleCloudPlatform/terraform-validator/policy"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"google.golang.org/api/iamassist"
)

var simulateCmd = &cobra.Command{
	Use:   "simulate <tfplan>",
	Short: "Simulate the policy changes in a Terraform plan by calling Policy Simulator.",
	Long: `
Policy Simluator is currently in whitelist only alpha. Contact the owner of this
repository if you would like to be whitelisted.

Policy Simulator (terraform-validator simulate) checks if any policy changes
in the Terraform plan will revoke accesses still in use. It does this by
replaying up to 90 days of access logs and reporting if any previously allowed
access would be denies under the new policies.

For more info, see https://cloud.google.com/iam/docs/simulating-access.

If any access revokations are seen, an error code of 2 is set.

Example:
  terraform-validator simulate ./example/terraform.tfplan \
    --project my-project \
    --ancestry organization/my-org/folder/my-folder \
`,
	PreRunE: func(c *cobra.Command, args []string) error {
		if len(args) != 1 {
			return errors.New("missing required argument <tfplan>")
		}
		return nil
	},
	RunE: runCmd,
}

func runCmd(c *cobra.Command, args []string) error {
	// Calling with offline=false because simulator cannot be run in offline mode.
	overlay, err := policy.BuildOverlay(args[0], flags.simulate.project, flags.simulate.ancestry, false)
	if err != nil {
		return errors.Wrap(err, "building overlay")
	}

	replay, err := runReplay(overlay)
	if err != nil {
		return err
	}

	if flags.simulate.outputJSON {
		fmt.Println(replay.json())
	} else {
		fmt.Println(replay.human())
	}

	return nil
}

func pretty(v interface{}) string {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Sprintf("error: %v", err)
	}
	return string(b)
}

// jsonReplay is a json ready representation of a successfully completed replay.
type jsonReplay struct {
	// Name is the name of the replay object.
	Name string `json:"name"`

	// Results is the list of results for this replay.
	Results []jsonReplayResult `json:"results"`
}

// jsonReplayResult is the result of replaying a single log entry.
type jsonReplayResult struct {
	// AccessTuple is the access that was replayed.
	AccessTuple jsonAccessTuple `json:"accessTuple,omitempty"`

	// LastSeen is the timestamp from the last log this AccessTuple was seen in.
	// Note: Granularity may be only to the day.
	// Format is ISO 8601.
	LastSeen string `json:"lastSeenDate,omitempty"`

	// Error is an error encountered when replaying the AccessTuple.
	// The tuple was not successfully replayed.
	// Only one of Error or Diff will be present.
	Error string `json:"error,omitempty"`

	// Diff is the result of successfully replaying the tuple.
	// Only one of Error or Diff will be present.
	Diff jsonReplayDiff `json:"diff,omitempty"`
}

// jsonAccessTuple is the information needed for an access check.
// This info is extracted from the replayed log entry.
type jsonAccessTuple struct {
	// FullResourceName is the full resource name that identifies the resource.
	FullResourceName string `json:"fullResourceName"`

	// Permission is the IAM permission to check for the specified member and resource.
	Permission string `json:"permission"`

	// Principal is the member, or principal, whose access you want to check.
	Principal string `json:"principal"`
}

// jsonReplayDiff is the difference between simulated and baseline accesses.
type jsonReplayDiff struct {
	// AccessChange: A single value interpretation of the difference between
	// baseline and simulated.
	//
	// Possible values:
	//   "ACCESS_CHANGE_TYPE_UNSPECIFIED" - Reserved
	//   "NO_CHANGE" - The two ExplainedAccesses are equal.
	//                 This includes the case where both baseline and simulated
	//                 are UNKNOWN, but the unknown information is equivalent.
	//   "UNKNOWN_CHANGE" - The baseline and simulated accesses are both
	//                      UNKNOWN, but the unknown information differs.
	//   "ACCESS_REVOKED" - The baseline access state is GRANTED and
	//                      the simulated access state is NOT_GRANTED
	//   "ACCESS_GAINED" - The baseline access state is NOT_GRANTED and
	//                     the simulated access state is GRANTED.
	//   "ACCESS_MAYBE_REVOKED" - The baseline access state is GRANTED and
	//                            the simulated access state is UNKNOWN.
	//   "ACCESS_MAYBE_GAINED" - The baseline state is NOT_GRANTED and
	//                           the simulated state is UNKNOWN.
	AccessChange string `json:"accessChange,omitempty"`

	// Baseline is the explained access state using baseline policies.
	Baseline jsonExplainedAccess `json:"baseline,omitempty"`

	// Simulated is the explained access state using simulated policies.
	Simulated jsonExplainedAccess `json:"simulated,omitempty"`
}

type jsonExplainedAccess struct {
	// AccessState is the overall access state.
	//
	// Possible values:
	//   "ACCESS_STATE_UNSPECIFIED" - Reserved.
	//   "GRANTED" - The member has the permission.
	//   "NOT_GRANTED" - The member does not have the permission.
	//   "UNKNOWN_CONDITIONAL" - The member has the permission only if a
	//                           condition expression evaluates to `true`.
	//   "UNKNOWN_INFO_DENIED" - The sender of the request does not have
	//                           access to all of the policies that affect
	//                           the access state.
	AccessState string `json:"accessState"`

	// Errors is the list of problems encountered when explaining this access.
	// This list explains why any UNKNOWN states were not able to be fully
	// evaluated.
	Errors []string `json:"errors,omitempty"`
}

// json formats replay results in json format.
func (r *jsonReplay) json() string {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Sprintf("error: %v", err)
	}
	return string(b)
}

// human formats replay results in human readable format.
func (r *jsonReplay) human() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Replay: %s\n", r.Name)
	for _, result := range r.Results {
		fmt.Fprintf(&b, "\n%s\n", result.human())
	}
	return b.String()
}

// json formats replay results in json format.
func (rr *jsonReplayResult) json() string {
	b, err := json.MarshalIndent(rr, "", "  ")
	if err != nil {
		return fmt.Sprintf("error: %v", err)
	}
	return string(b)
}

// human formats replay results in human readable format.
func (rr *jsonReplayResult) human() string {
	if rr.Error != "" {
		return fmt.Sprintf("ERROR: %s: %s", rr.AccessTuple.human(), rr.Error)
	}
	result := []string{fmt.Sprintf("%s: %s", rr.Diff.AccessChange, rr.AccessTuple.human())}
	if len(rr.Diff.Baseline.Errors) > 0 {
		result = append(result, "Baseline Unknowns")
		result = append(result, rr.Diff.Baseline.Errors...)
	}
	if len(rr.Diff.Simulated.Errors) > 0 {
		result = append(result, "Simulated Unknowns")
		result = append(result, rr.Diff.Simulated.Errors...)
	}
	return strings.Join(result, "\n")
}

func (at *jsonAccessTuple) human() string {
	return fmt.Sprintf("(%s, %s, %s)", at.Principal, at.Permission, at.FullResourceName)
}

func jsonReplayFromAssistV1alpha3(replay *iamassist.GoogleIamAssistV1alpha3Replay) jsonReplay {
	r := jsonReplay{
		Name:    replay.Name,
		Results: []jsonReplayResult{},
	}

	for _, rr := range replay.Errors {
		r.Results = append(r.Results, jsonReplayResultFromAssistV1alpha3(rr))
	}
	for _, rr := range replay.Diffs {
		r.Results = append(r.Results, jsonReplayResultFromAssistV1alpha3(rr))
	}

	return r
}

func jsonReplayResultFromAssistV1alpha3(result *iamassist.GoogleIamAssistV1alpha3ReplayResult) jsonReplayResult {
	rr := jsonReplayResult{
		AccessTuple: jsonAccessTuple{
			FullResourceName: result.AccessTuple.FullResourceName,
			Permission:       result.AccessTuple.Permission,
			Principal:        result.AccessTuple.Principal,
		},
		LastSeen: iso8601FromGoogleDate(result.LastSeenDate),
	}

	if result.Error != nil {
		b, err := result.Error.MarshalJSON()
		if err != nil {
			rr.Error = err.Error()
		}
		rr.Error = string(b)
		return rr
	}

	rr.Diff = jsonReplayDiffFromAssistV1alpha3(result.Diff)

	return rr
}

func jsonReplayDiffFromAssistV1alpha3(diff *iamassist.GoogleIamAssistV1alpha3ReplayDiff) jsonReplayDiff {
	if diff == nil || diff.AccessDiff == nil {
		return jsonReplayDiff{}
	}
	return jsonReplayDiff{
		AccessChange: diff.AccessDiff.AccessChange,
		Baseline:     jsonExplainedAccessFromAssistV1alpha3(diff.AccessDiff.Baseline),
		Simulated:    jsonExplainedAccessFromAssistV1alpha3(diff.AccessDiff.Simulated),
	}
}

func jsonExplainedAccessFromAssistV1alpha3(ea *iamassist.GoogleIamAssistV1alpha3ExplainedAccess) jsonExplainedAccess {
	if ea == nil {
		return jsonExplainedAccess{}
	}

	return jsonExplainedAccess{
		AccessState: ea.AccessState,
		Errors:      statusListToStringList(ea.Errors),
	}
}

func statusListToStringList(statuses []*iamassist.GoogleRpcStatus) []string {
	var s []string
	for _, val := range statuses {
		b, err := val.MarshalJSON()
		if err != nil {
			s = append(s, err.Error())
			continue
		}
		s = append(s, string(b))
	}
	return s
}

func iso8601FromGoogleDate(date *iamassist.GoogleTypeDate) string {
	if date == nil {
		return ""
	}
	t := time.Date(int(date.Year), time.Month(date.Month), int(date.Day), 0, 0, 0, 0, time.UTC)
	return t.Format("2006-01-02")
}

// runReplay runs a replay using the provided overlay and returns the results of that Replay.
func runReplay(overlay policy.Overlay) (jsonReplay, error) {
	// Create the client
	ctx := context.Background()
	client, err := iamassist.NewService(ctx)
	if err != nil {
		log.Fatalf("iamassist.NewService(): %v", err)
	}

	// Make the call
	req := &iamassist.GoogleIamAssistV1alpha3Replay{
		Config: &iamassist.GoogleIamAssistV1alpha3ReplayConfig{
			LogSource:     "RECENT_ACCESSES",
			PolicyOverlay: convertOverlay(overlay),
		},
	}
	op, err := client.Replays.Create(req).Do()
	if err != nil {
		return jsonReplay{}, errors.Wrap(err, "creating error")
	}

	// Poll GetOperation until it's done.
	fmt.Printf("Waiting for %s ", op.Name)
	for !op.Done {
		time.Sleep(1 * time.Second)
		// Make sure you overwrite the existing variables.
		// Redeclaring will cause infinite loop.
		op, err = client.Operations.Get(op.Name).Do()
		if err != nil {
			fmt.Printf("\n%#v\n", err)
			return jsonReplay{}, errors.Wrap(err, "waiting for Replay to complete")
		}
		fmt.Printf(".")
	}
	fmt.Printf("Done\n")

	// Error means no replay exists.
	if op.Error != nil {
		b, _ := op.Error.MarshalJSON()
		return jsonReplay{}, fmt.Errorf("%s: %s", op.Name, string(b))
	}

	// If error is empty, we expect a replay.
	var replay *iamassist.GoogleIamAssistV1alpha3Replay
	if err := json.Unmarshal(op.Response, &replay); err != nil {
		return jsonReplay{}, errors.Wrap(err, "getting Replay")
	}

	return jsonReplayFromAssistV1alpha3(replay), nil
}

func convertOverlay(o policy.Overlay) map[string]iamassist.GoogleIamV1Policy {
	res := map[string]iamassist.GoogleIamV1Policy{}
	for r, p := range o {
		res[r] = convertPolicy(p)
	}
	return res
}

func convertPolicy(p *google.IAMPolicy) iamassist.GoogleIamV1Policy {
	if p == nil {
		return iamassist.GoogleIamV1Policy{}
	}
	return iamassist.GoogleIamV1Policy{
		Bindings: convertBindings(p.Bindings),
	}
}

func convertBindings(bindings []google.IAMBinding) []*iamassist.GoogleIamV1Binding {
	var res []*iamassist.GoogleIamV1Binding
	for _, b := range bindings {
		res = append(res, &iamassist.GoogleIamV1Binding{
			Members: b.Members,
			Role:    b.Role,
		})
	}
	return res
}
