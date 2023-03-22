package watcher

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestImageIDWLIDsMapNew(t *testing.T) {
	var iwMap *imageIDWLIDMap
	iwMap = NewImageIDWLIDsMap()

	assert.NotNilf(t, iwMap, "Returned map should not be nil")
}

func TestImageIDWLIDsMapSetAndGet(t *testing.T) {
	tt := []struct {
		name        string
		inputKVs    map[string][]string
		expectedKVs map[string][]string
		expectedOks map[string]bool
	}{
		{
			name: "Storing a single value should return a matching value",
			inputKVs: map[string][]string{
				"someImageID": {"someWLID"},
			},
			expectedKVs: map[string][]string{
				"someImageID": {"someWLID"},
			},
			expectedOks: map[string]bool{
				"someImageID": true,
			},
		},
		{
			name: "Storing multiple keys should return matching values",
			inputKVs: map[string][]string{
				"someImageID":      {"someWLID"},
				"someOtherImageID": {"someOtherWLID"},
			},
			expectedKVs: map[string][]string{
				"someImageID":      {"someWLID"},
				"someOtherImageID": {"someOtherWLID"},
			},
			expectedOks: map[string]bool{
				"someImageID":      true,
				"someOtherImageID": true,
			},
		},
		{
			name:     "Getting from empty map should return a NOT ok flag",
			inputKVs: map[string][]string{},
			expectedKVs: map[string][]string{
				"someImageID": nil,
			},
			expectedOks: map[string]bool{
				"someImageID": false,
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			iwMap := NewImageIDWLIDsMap()

			for k, v := range tc.inputKVs {
				iwMap.Set(k, v)
			}

			actualKVs := map[string][]string{}
			for k := range tc.expectedKVs {
				actualValue, _ := iwMap.Get(k)
				actualKVs[k] = actualValue
			}

			actualOks := map[string]bool{}
			for k := range tc.expectedOks {
				_, ok := iwMap.Get(k)
				actualOks[k] = ok
			}

			assert.Equalf(t, tc.expectedKVs, actualKVs, "Stored value must match the input value")
			assert.Equalf(t, tc.expectedOks, actualOks, "Actual OKs must match the expected OKs")
		})
	}
}

func TestImageIDWLIDsMapGetResultImmutable(t *testing.T) {
	tt := []struct {
		name        string
		startingMap map[string][]string
		appendInput []string
		testKey     string
		expected    []string
	}{
		{
			name: "Plain appending to Get result of a map should not mutate the underlying map",
			startingMap: map[string][]string{
				"some": {"first", "second"},
			},
			testKey:     "some",
			appendInput: []string{"INTRUDER"},
			expected:    []string{"first", "second"},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			iwMap := NewImageIDWLIDsMap()
			for k, v := range tc.startingMap {
				iwMap.Set(k, v)
			}
			got, _ := iwMap.Get(tc.testKey)

			for _, input := range tc.appendInput {
				got = append(got, input)
			}

			actual, _ := iwMap.Get(tc.testKey)

			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestImageIDWLIDsMapClear(t *testing.T) {
	tt := []struct {
		name string
		startingValues map[string][]string
	}{
		{
			name: "Clearing a non-empty map should make it an empty map",
			startingValues: map[string][]string{
				"imageID": {"wlid01", "wlid02"},
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			iwMap := NewImageIDWLIDsMap()
			for k, v := range tc.startingValues {
				iwMap.Set(k, v)
			}

			iwMap.Clear()

			remainingValues := map[string][]string{}
			for k := range tc.startingValues {
				remainingValue, ok := iwMap.Get(k)
				if ok {
					remainingValues[k] = remainingValue
				}
			}
			expectedRemainingValues := map[string][]string{}
			assert.Equal(t, expectedRemainingValues, remainingValues)
		})
	}
}
