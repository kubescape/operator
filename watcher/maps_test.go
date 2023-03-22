package watcher

import (
	"testing"

	sets "github.com/deckarep/golang-set/v2"
	"github.com/stretchr/testify/assert"
)

func TestWLIDSetNew(t *testing.T) {
	tt := []struct {
		name        string
		inputValues []string
	}{
		{
			name:        "The created set should contain the input values",
			inputValues: []string{"a", "b"},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			ws := NewWLIDSet(tc.inputValues...)

			expectedValues := sets.NewSet(tc.inputValues...)
			if !expectedValues.Equal(ws) {
				t.Errorf("Given sets are not equal.")

			}
		})
	}
}

func TestImageIDWLIDsMapNew(t *testing.T) {
	var iwMap *imageIDWLIDMap
	iwMap = NewImageIDWLIDsMap()

	assert.NotNilf(t, iwMap, "Returned map should not be nil")
}

func TestImageIDWLIDsMapSetAndGet(t *testing.T) {
	tt := []struct {
		name        string
		inputKVs    map[string]wlidSet
		expectedKVs map[string]wlidSet
		expectedOks map[string]bool
	}{
		{
			name: "Storing a single value should return a matching value",
			inputKVs: map[string]wlidSet{
				"someImageID": NewWLIDSet("someWLID"),
			},
			expectedKVs: map[string]wlidSet{
				"someImageID": NewWLIDSet("someWLID"),
			},
			expectedOks: map[string]bool{
				"someImageID": true,
			},
		},
		{
			name: "Storing multiple keys should return matching values",
			inputKVs: map[string]wlidSet{
				"someImageID":      NewWLIDSet("someWLID"),
				"someOtherImageID": NewWLIDSet("someOtherWLID"),
			},
			expectedKVs: map[string]wlidSet{
				"someImageID":      NewWLIDSet("someWLID"),
				"someOtherImageID": NewWLIDSet("someOtherWLID"),
			},
			expectedOks: map[string]bool{
				"someImageID":      true,
				"someOtherImageID": true,
			},
		},
		{
			name:     "Getting from empty map should return a NOT ok flag",
			inputKVs: map[string]wlidSet{},
			expectedKVs: map[string]wlidSet{
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

			actualKVs := map[string]wlidSet{}
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
		startingMap map[string]wlidSet
		appendInput []string
		testKey     string
		expected    wlidSet
	}{
		{
			name: "Plain appending to Get result of a map should not mutate the underlying map",
			startingMap: map[string]wlidSet{
				"some": NewWLIDSet("first", "second"),
			},
			testKey:     "some",
			appendInput: []string{"INTRUDER"},
			expected:    NewWLIDSet("first", "second"),
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
				got.Add(input)
			}

			actual, _ := iwMap.Get(tc.testKey)

			if !actual.Equal(tc.expected) {
				t.Errorf("Sets are not equal. Got: %v, want: %v", actual, tc.expected)
			}
		})
	}
}

func TestImageIDWLIDsMapClear(t *testing.T) {
	tt := []struct {
		name           string
		startingValues map[string]wlidSet
	}{
		{
			name: "Clearing a non-empty map should make it an empty map",
			startingValues: map[string]wlidSet{
				"imageID": NewWLIDSet("wlid01", "wlid02"),
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

			remainingValues := map[string]wlidSet{}
			for k := range tc.startingValues {
				remainingValue, ok := iwMap.Get(k)
				if ok {
					remainingValues[k] = remainingValue
				}
			}
			expectedRemainingValues := map[string]wlidSet{}
			assert.Equal(t, expectedRemainingValues, remainingValues)
		})
	}
}

func TestImageIDWLIDsAdd(t *testing.T) {
	tt := []struct {
		name           string
		startingValues map[string][]string
	}{
		{
			name: "Adding an image ID to an empty map should be reflected",
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			assert.FailNow(t, "TODO")
		})
	}
}
