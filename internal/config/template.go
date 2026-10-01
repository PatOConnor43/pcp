package config

import (
	"fmt"
	"text/template"
	"text/template/parse"
)

// Template is a config value that may reference credentials via the
// `secret "<name>"` and `token "<name>"` template functions.
//
// Arguments to those functions must be string literals so that references can
// be validated when the config is loaded, before any request is served.
type Template struct {
	raw     string
	secrets []string
	tokens  []string
}

// stubFuncs lets templates parse without real credential lookups. Rendering
// re-parses Raw with live implementations.
var stubFuncs = template.FuncMap{
	"secret": func(string) string { return "" },
	"token":  func(string) string { return "" },
}

// ParseTemplate parses s and extracts its secret and token references.
func ParseTemplate(s string) (Template, error) {
	t, err := template.New("").Funcs(stubFuncs).Option("missingkey=error").Parse(s)
	if err != nil {
		return Template{}, err
	}
	tpl := Template{raw: s}
	if t.Tree == nil {
		return tpl, nil
	}
	if err := walk(t.Tree.Root, tpl.collect); err != nil {
		return Template{}, err
	}
	return tpl, nil
}

// UnmarshalYAML implements yaml.InterfaceUnmarshaler.
func (t *Template) UnmarshalYAML(unmarshal func(any) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	parsed, err := ParseTemplate(s)
	if err != nil {
		return err
	}
	*t = parsed
	return nil
}

// Raw returns the unparsed template text.
func (t Template) Raw() string { return t.raw }

// Secrets returns the secret names referenced by the template.
func (t Template) Secrets() []string { return t.secrets }

// Tokens returns the token source names referenced by the template.
func (t Template) Tokens() []string { return t.tokens }

func (t *Template) collect(cmd *parse.CommandNode) error {
	ident, ok := cmd.Args[0].(*parse.IdentifierNode)
	if !ok || (ident.Ident != "secret" && ident.Ident != "token") {
		return nil
	}
	if len(cmd.Args) != 2 {
		return fmt.Errorf("%s takes exactly one string literal argument", ident.Ident)
	}
	name, ok := cmd.Args[1].(*parse.StringNode)
	if !ok {
		return fmt.Errorf("%s argument must be a string literal", ident.Ident)
	}
	if name.Text == "" {
		return fmt.Errorf("%s name must not be empty", ident.Ident)
	}
	if ident.Ident == "secret" {
		t.secrets = appendUnique(t.secrets, name.Text)
	} else {
		t.tokens = appendUnique(t.tokens, name.Text)
	}
	return nil
}

// walk calls fn for every command node in the tree.
func walk(n parse.Node, fn func(*parse.CommandNode) error) error {
	switch n := n.(type) {
	case nil:
		return nil
	case *parse.ListNode:
		if n == nil {
			return nil
		}
		for _, c := range n.Nodes {
			if err := walk(c, fn); err != nil {
				return err
			}
		}
	case *parse.ActionNode:
		return walk(n.Pipe, fn)
	case *parse.PipeNode:
		if n == nil {
			return nil
		}
		for _, c := range n.Cmds {
			if err := walk(c, fn); err != nil {
				return err
			}
		}
	case *parse.CommandNode:
		if err := fn(n); err != nil {
			return err
		}
		for _, a := range n.Args {
			if err := walk(a, fn); err != nil {
				return err
			}
		}
	case *parse.ChainNode:
		return walk(n.Node, fn)
	case *parse.IfNode:
		return walkBranch(&n.BranchNode, fn)
	case *parse.RangeNode:
		return walkBranch(&n.BranchNode, fn)
	case *parse.WithNode:
		return walkBranch(&n.BranchNode, fn)
	case *parse.TemplateNode:
		return walk(n.Pipe, fn)
	}
	return nil
}

func walkBranch(b *parse.BranchNode, fn func(*parse.CommandNode) error) error {
	for _, n := range []parse.Node{b.Pipe, b.List, b.ElseList} {
		if err := walk(n, fn); err != nil {
			return err
		}
	}
	return nil
}

func appendUnique(s []string, v string) []string {
	for _, e := range s {
		if e == v {
			return s
		}
	}
	return append(s, v)
}
