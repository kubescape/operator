package sbomexport

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"text/template"
)

// Namespace annotations that override the layout for one namespace. Each one
// is optional; what a namespace does not set comes from the defaults.
const (
	// AnnotationRootProject is the root project, as "name:version" or a project UUID.
	AnnotationRootProject = "kubescape.io/dtrack-root-project"
	// AnnotationRootProjectCreate is "true" or "false".
	AnnotationRootProjectCreate = "kubescape.io/dtrack-root-project-create"
	// AnnotationParent is the parent project, as "name:version" or a project UUID.
	AnnotationParent = "kubescape.io/dtrack-parent"
	// AnnotationParentCreate is "true" or "false".
	AnnotationParentCreate = "kubescape.io/dtrack-parent-create"
	// AnnotationProjectName is a template for the image project's name.
	AnnotationProjectName = "kubescape.io/dtrack-project-name"
)

// TemplateData is what the layout templates can use, e.g.
// "{{ .Cluster }}/{{ .Namespace }}" or `{{ index .Labels "team" }}`.
type TemplateData struct {
	Cluster    string
	Namespace  string
	Repository string
	Tag        string
	// Labels are the namespace's labels.
	Labels map[string]string
}

// Collection is a collection project in the layout: the root, or the parent of
// an image's project. Name and Version are templates.
type Collection struct {
	Name    string
	Version string
	// Create lets the exporter create the project when it is missing.
	Create bool
}

// Layout is where images go in Dependency-Track, by default. Name and Version
// are templates for the image's project.
type Layout struct {
	Root    Collection
	Parent  Collection
	Name    string
	Version string
}

// projectRef points at a Dependency-Track project by UUID, or by name and version.
type projectRef struct {
	uuid          string
	name, version string
}

func (r projectRef) String() string {
	if r.uuid != "" {
		return r.uuid
	}
	return r.name + ":" + r.version
}

// placement is where one image of one namespace goes.
type placement struct {
	root          projectRef
	rootCreate    bool
	parent        projectRef
	parentCreate  bool
	name, version string // the image's project
}

// namespaceInfo is what the layout needs to know about a namespace.
type namespaceInfo struct {
	name        string
	labels      map[string]string
	annotations map[string]string
}

var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// parseRef reads an annotation's project reference: a UUID, or "name:version",
// split at the last colon.
func parseRef(s string) (projectRef, error) {
	s = strings.TrimSpace(s)
	if uuidPattern.MatchString(s) {
		return projectRef{uuid: strings.ToLower(s)}, nil
	}
	i := strings.LastIndex(s, ":")
	if i <= 0 || i == len(s)-1 {
		return projectRef{}, fmt.Errorf("%q is neither a project UUID nor name:version", s)
	}
	return projectRef{name: s[:i], version: s[i+1:]}, nil
}

// layout resolves placements from the default Layout and namespace annotations.
type layout struct {
	cluster string
	root    [2]*template.Template // name, version
	parent  [2]*template.Template
	project [2]*template.Template
	defs    Layout

	mu         sync.Mutex
	nameByText map[string]*template.Template // parsed AnnotationProjectName values
}

func parseTemplate(field, text string) (*template.Template, error) {
	t, err := template.New(field).Option("missingkey=error").Parse(text)
	if err != nil {
		return nil, fmt.Errorf("%s %q: %w", field, text, err)
	}
	return t, nil
}

// newLayout parses the default templates and checks that they render.
func newLayout(cluster string, l Layout) (*layout, error) {
	x := &layout{cluster: cluster, defs: l, nameByText: map[string]*template.Template{}}
	var errs []error
	for _, f := range []struct {
		dst   **template.Template
		field string
		text  string
	}{
		{&x.root[0], "rootProject.name", l.Root.Name},
		{&x.root[1], "rootProject.version", l.Root.Version},
		{&x.parent[0], "project.parent.name", l.Parent.Name},
		{&x.parent[1], "project.parent.version", l.Parent.Version},
		{&x.project[0], "project.name", l.Name},
		{&x.project[1], "project.version", l.Version},
	} {
		t, err := parseTemplate(f.field, f.text)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		*f.dst = t
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	sample := TemplateData{Cluster: cluster, Namespace: "default", Repository: "docker.io/library/nginx", Tag: "1.27", Labels: map[string]string{}}
	for _, t := range []*template.Template{x.root[0], x.root[1], x.parent[0], x.parent[1], x.project[0], x.project[1]} {
		if _, err := render(t, sample); err != nil {
			errs = append(errs, err)
		}
	}
	return x, errors.Join(errs...)
}

// render executes t and rejects an empty result.
func render(t *template.Template, data TemplateData) (string, error) {
	var b bytes.Buffer
	if err := t.Execute(&b, data); err != nil {
		return "", fmt.Errorf("render %s: %w", t.Name(), err)
	}
	out := strings.TrimSpace(b.String())
	if out == "" {
		return "", fmt.Errorf("render %s: empty result", t.Name())
	}
	return out, nil
}

func (x *layout) projectNameTemplate(text string) (*template.Template, error) {
	x.mu.Lock()
	defer x.mu.Unlock()
	if t, ok := x.nameByText[text]; ok {
		return t, nil
	}
	t, err := parseTemplate(AnnotationProjectName, text)
	if err != nil {
		return nil, err
	}
	x.nameByText[text] = t
	return t, nil
}

// boolAnnotation reads a "true"/"false" annotation, or def when it is not set.
func boolAnnotation(ann map[string]string, key string, def bool) (bool, error) {
	v, ok := ann[key]
	if !ok {
		return def, nil
	}
	b, err := strconv.ParseBool(strings.TrimSpace(v))
	if err != nil {
		return false, fmt.Errorf("annotation %s: %q is not true or false", key, v)
	}
	return b, nil
}

// resolve returns where repository:tag, running in ns, goes. Each annotation
// replaces only the setting it names.
func (x *layout) resolve(ns namespaceInfo, repository, tag string) (placement, error) {
	data := TemplateData{Cluster: x.cluster, Namespace: ns.name, Repository: repository, Tag: tag, Labels: ns.labels}
	if data.Labels == nil {
		data.Labels = map[string]string{}
	}
	ann := ns.annotations
	var p placement
	var err error

	if p.root, err = x.collectionRef(ann, AnnotationRootProject, x.root, data); err != nil {
		return placement{}, err
	}
	if p.rootCreate, err = boolAnnotation(ann, AnnotationRootProjectCreate, x.defs.Root.Create); err != nil {
		return placement{}, err
	}
	if p.parent, err = x.collectionRef(ann, AnnotationParent, x.parent, data); err != nil {
		return placement{}, err
	}
	if p.parentCreate, err = boolAnnotation(ann, AnnotationParentCreate, x.defs.Parent.Create); err != nil {
		return placement{}, err
	}

	nameTmpl := x.project[0]
	if text, ok := ann[AnnotationProjectName]; ok {
		if nameTmpl, err = x.projectNameTemplate(text); err != nil {
			return placement{}, err
		}
	}
	if p.name, err = render(nameTmpl, data); err != nil {
		return placement{}, err
	}
	if p.version, err = render(x.project[1], data); err != nil {
		return placement{}, err
	}
	return p, nil
}

// collectionRef reads the reference from the annotation key, or renders the
// default name and version templates.
func (x *layout) collectionRef(ann map[string]string, key string, defs [2]*template.Template, data TemplateData) (projectRef, error) {
	if v, ok := ann[key]; ok {
		r, err := parseRef(v)
		if err != nil {
			return projectRef{}, fmt.Errorf("annotation %s: %w", key, err)
		}
		return r, nil
	}
	name, err := render(defs[0], data)
	if err != nil {
		return projectRef{}, err
	}
	version, err := render(defs[1], data)
	if err != nil {
		return projectRef{}, err
	}
	return projectRef{name: name, version: version}, nil
}
