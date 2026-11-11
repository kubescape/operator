package sbomexport

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseRef(t *testing.T) {
	tt := []struct {
		in      string
		want    projectRef
		wantErr bool
	}{
		{in: "Payments Team:current", want: projectRef{name: "Payments Team", version: "current"}},
		{in: "a:b:c", want: projectRef{name: "a:b", version: "c"}},
		{in: "0A1B2C3D-0000-4000-8000-000000000001", want: projectRef{uuid: "0a1b2c3d-0000-4000-8000-000000000001"}},
		{in: "Payments Team", wantErr: true},
		{in: ":current", wantErr: true},
		{in: "Payments Team:", wantErr: true},
	}
	for _, tc := range tt {
		t.Run(tc.in, func(t *testing.T) {
			got, err := parseRef(tc.in)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestLayoutDefaultsBuildTheClusterNamespaceTree(t *testing.T) {
	l, err := newLayout("prod", defaultLayout)
	require.NoError(t, err)

	p, err := l.resolve(namespaceInfo{name: "apps"}, "docker.io/library/redis", "8")

	require.NoError(t, err)
	assert.Equal(t, placement{
		root:         projectRef{name: "prod", version: "current"},
		rootCreate:   true,
		parent:       projectRef{name: "prod/apps", version: "current"},
		parentCreate: true,
		name:         "prod/apps/docker.io/library/redis",
		version:      "8",
	}, p)
}

func TestLayoutTemplatesSeeTheNamespaceLabels(t *testing.T) {
	byTeam := defaultLayout
	byTeam.Parent.Name = `{{ .Cluster }}/{{ index .Labels "team" }}`
	l, err := newLayout("prod", byTeam)
	require.NoError(t, err)

	p, err := l.resolve(namespaceInfo{name: "apps", labels: map[string]string{"team": "payments"}}, "docker.io/library/redis", "8")

	require.NoError(t, err)
	assert.Equal(t, projectRef{name: "prod/payments", version: "current"}, p.parent)
}

func TestLayoutAnnotationsOverrideOneSettingEach(t *testing.T) {
	l, err := newLayout("prod", defaultLayout)
	require.NoError(t, err)
	tt := []struct {
		name        string
		annotations map[string]string
		check       func(t *testing.T, p placement)
	}{
		{
			name:        "root project",
			annotations: map[string]string{AnnotationRootProject: "Finance:current", AnnotationRootProjectCreate: "false"},
			check: func(t *testing.T, p placement) {
				assert.Equal(t, projectRef{name: "Finance", version: "current"}, p.root)
				assert.False(t, p.rootCreate)
				assert.Equal(t, projectRef{name: "prod/apps", version: "current"}, p.parent, "the parent keeps its default")
				assert.True(t, p.parentCreate)
			},
		},
		{
			name:        "parent by UUID",
			annotations: map[string]string{AnnotationParent: "0a1b2c3d-0000-4000-8000-000000000001", AnnotationParentCreate: "false"},
			check: func(t *testing.T, p placement) {
				assert.Equal(t, projectRef{uuid: "0a1b2c3d-0000-4000-8000-000000000001"}, p.parent)
				assert.False(t, p.parentCreate)
				assert.Equal(t, projectRef{name: "prod", version: "current"}, p.root, "the root keeps its default")
			},
		},
		{
			name:        "project name",
			annotations: map[string]string{AnnotationProjectName: "{{ .Namespace }}-{{ .Repository }}"},
			check: func(t *testing.T, p placement) {
				assert.Equal(t, "apps-docker.io/library/redis", p.name)
				assert.Equal(t, "8", p.version, "the version keeps its default")
			},
		},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			p, err := l.resolve(namespaceInfo{name: "apps", annotations: tc.annotations}, "docker.io/library/redis", "8")
			require.NoError(t, err)
			tc.check(t, p)
		})
	}
}

func TestLayoutRejectsAnnotationsItCannotUse(t *testing.T) {
	l, err := newLayout("prod", defaultLayout)
	require.NoError(t, err)
	tt := []struct {
		name        string
		annotations map[string]string
	}{
		{"a reference without a version", map[string]string{AnnotationParent: "Payments Team"}},
		{"a create flag that is not a boolean", map[string]string{AnnotationParentCreate: "maybe"}},
		{"a template that does not parse", map[string]string{AnnotationProjectName: "{{ .Repository"}},
		{"a template with an unknown field", map[string]string{AnnotationProjectName: "{{ .Digest }}"}},
		{"a template that renders nothing", map[string]string{AnnotationProjectName: `{{ index .Labels "team" }}`}},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			_, err := l.resolve(namespaceInfo{name: "apps", annotations: tc.annotations}, "docker.io/library/redis", "8")
			assert.Error(t, err)
		})
	}
}
