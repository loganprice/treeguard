package parser

import (
	"fmt"
	"path/filepath"
	"strings"
	"sync"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"
	tree_sitter_c "github.com/tree-sitter/tree-sitter-c/bindings/go"
	tree_sitter_cpp "github.com/tree-sitter/tree-sitter-cpp/bindings/go"
	tree_sitter_go "github.com/tree-sitter/tree-sitter-go/bindings/go"
	tree_sitter_java "github.com/tree-sitter/tree-sitter-java/bindings/go"
	tree_sitter_javascript "github.com/tree-sitter/tree-sitter-javascript/bindings/go"
	tree_sitter_json "github.com/tree-sitter/tree-sitter-json/bindings/go"
	tree_sitter_php "github.com/tree-sitter/tree-sitter-php/bindings/go"
	tree_sitter_python "github.com/tree-sitter/tree-sitter-python/bindings/go"
	tree_sitter_ruby "github.com/tree-sitter/tree-sitter-ruby/bindings/go"
	tree_sitter_rust "github.com/tree-sitter/tree-sitter-rust/bindings/go"
	tree_sitter_typescript "github.com/tree-sitter/tree-sitter-typescript/bindings/go"

	tree_sitter_dockerfile "github.com/loganprice/tree-sitter-docker/bindings/go"
)

// LanguageDef defines a supported programming language and its Tree-sitter grammar.
type LanguageDef struct {
	Name       string
	Extensions []string
	Language   func() *tree_sitter.Language
}

var (
	registryMu sync.RWMutex
	languages  = map[string]LanguageDef{}
	extMap     = map[string]string{}
)

func init() {
	RegisterLanguage(LanguageDef{
		Name:       "python",
		Extensions: []string{".py", ".pyi"},
		Language: func() *tree_sitter.Language {
			return tree_sitter.NewLanguage(tree_sitter_python.Language())
		},
	})

	RegisterLanguage(LanguageDef{
		Name:       "javascript",
		Extensions: []string{".js", ".jsx", ".mjs", ".cjs"},
		Language: func() *tree_sitter.Language {
			return tree_sitter.NewLanguage(tree_sitter_javascript.Language())
		},
	})

	RegisterLanguage(LanguageDef{
		Name:       "typescript",
		Extensions: []string{".ts", ".mts", ".cts"},
		Language: func() *tree_sitter.Language {
			return tree_sitter.NewLanguage(tree_sitter_typescript.LanguageTypescript())
		},
	})

	RegisterLanguage(LanguageDef{
		Name:       "tsx",
		Extensions: []string{".tsx"},
		Language: func() *tree_sitter.Language {
			return tree_sitter.NewLanguage(tree_sitter_typescript.LanguageTSX())
		},
	})

	RegisterLanguage(LanguageDef{
		Name:       "go",
		Extensions: []string{".go"},
		Language: func() *tree_sitter.Language {
			return tree_sitter.NewLanguage(tree_sitter_go.Language())
		},
	})

	RegisterLanguage(LanguageDef{
		Name:       "java",
		Extensions: []string{".java"},
		Language: func() *tree_sitter.Language {
			return tree_sitter.NewLanguage(tree_sitter_java.Language())
		},
	})

	RegisterLanguage(LanguageDef{
		Name:       "rust",
		Extensions: []string{".rs"},
		Language: func() *tree_sitter.Language {
			return tree_sitter.NewLanguage(tree_sitter_rust.Language())
		},
	})

	RegisterLanguage(LanguageDef{
		Name:       "ruby",
		Extensions: []string{".rb", ".rake", ".gemspec"},
		Language: func() *tree_sitter.Language {
			return tree_sitter.NewLanguage(tree_sitter_ruby.Language())
		},
	})

	RegisterLanguage(LanguageDef{
		Name:       "c",
		Extensions: []string{".c", ".h"},
		Language: func() *tree_sitter.Language {
			return tree_sitter.NewLanguage(tree_sitter_c.Language())
		},
	})

	RegisterLanguage(LanguageDef{
		Name:       "cpp",
		Extensions: []string{".cpp", ".cc", ".cxx", ".hpp", ".hxx"},
		Language: func() *tree_sitter.Language {
			return tree_sitter.NewLanguage(tree_sitter_cpp.Language())
		},
	})

	RegisterLanguage(LanguageDef{
		Name:       "php",
		Extensions: []string{".php"},
		Language: func() *tree_sitter.Language {
			return tree_sitter.NewLanguage(tree_sitter_php.LanguagePHP())
		},
	})

	RegisterLanguage(LanguageDef{
		Name:       "json",
		Extensions: []string{".json"},
		Language: func() *tree_sitter.Language {
			return tree_sitter.NewLanguage(tree_sitter_json.Language())
		},
	})

	RegisterLanguage(LanguageDef{
		Name:       "dockerfile",
		Extensions: []string{".dockerfile", ".containerfile"},
		Language: func() *tree_sitter.Language {
			return tree_sitter.NewLanguage(tree_sitter_dockerfile.Language())
		},
	})
}

// RegisterLanguage registers a new language definition.
func RegisterLanguage(def LanguageDef) {
	registryMu.Lock()
	defer registryMu.Unlock()

	normalized := strings.ToLower(def.Name)
	languages[normalized] = def
	for _, ext := range def.Extensions {
		extMap[strings.ToLower(ext)] = normalized
	}
}

// DetectLanguage detects the language name from a file path.
func DetectLanguage(filePath string) (string, error) {
	registryMu.RLock()
	defer registryMu.RUnlock()

	base := strings.ToLower(filepath.Base(filePath))
	if base == "dockerfile" || strings.HasPrefix(base, "dockerfile.") || base == "containerfile" || strings.HasPrefix(base, "containerfile.") {
		return "dockerfile", nil
	}

	ext := strings.ToLower(filepath.Ext(filePath))
	if lang, ok := extMap[ext]; ok {
		return lang, nil
	}
	return "", fmt.Errorf("unsupported file extension %q for file %s", ext, filePath)
}

// GetLanguage returns the tree_sitter.Language for a given language name.
func GetLanguage(langName string) (*tree_sitter.Language, error) {
	registryMu.RLock()
	defer registryMu.RUnlock()

	normalized := strings.ToLower(langName)
	def, ok := languages[normalized]
	if !ok {
		return nil, fmt.Errorf("unsupported language %q", langName)
	}
	return def.Language(), nil
}

// SupportedLanguages returns a list of supported language names.
func SupportedLanguages() []string {
	registryMu.RLock()
	defer registryMu.RUnlock()

	list := make([]string, 0, len(languages))
	for name := range languages {
		list = append(list, name)
	}
	return list
}

// SupportedExtensions returns a list of all registered file extensions.
func SupportedExtensions() []string {
	registryMu.RLock()
	defer registryMu.RUnlock()

	exts := make([]string, 0, len(extMap))
	for ext := range extMap {
		exts = append(exts, ext)
	}
	return exts
}

// IsSupportedFile checks if the given file has a supported extension.
func IsSupportedFile(filePath string) bool {
	registryMu.RLock()
	defer registryMu.RUnlock()

	base := strings.ToLower(filepath.Base(filePath))
	if base == "dockerfile" || strings.HasPrefix(base, "dockerfile.") || base == "containerfile" || strings.HasPrefix(base, "containerfile.") {
		return true
	}

	ext := strings.ToLower(filepath.Ext(filePath))
	_, ok := extMap[ext]
	return ok
}
