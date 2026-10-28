## Description

<!-- Provide a brief summary of the changes introduced by this pull request. -->

## Related Issues

<!-- Link any related issues or discussions (e.g. Closes #123, Fixes #456). -->

## Type of Change

- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] New rule / rule enhancement (adds or modifies Rego security rules)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Refactoring / Code hygiene
- [ ] Documentation update
- [ ] CI/CD or tooling

## Language / Parser Impact

<!-- If this PR modifies parser bindings or adds rules, specify the affected language(s). -->
- [ ] C / C++
- [ ] Go
- [ ] Java
- [ ] JavaScript / TypeScript / TSX
- [ ] JSON
- [ ] PHP
- [ ] Python
- [ ] Ruby
- [ ] Rust
- [ ] Dockerfile / Containerfile
- [ ] Not language specific

## Checklist

- [ ] I have read the [CONTRIBUTING.md](https://github.com/loganprice/treeguard/blob/main/CONTRIBUTING.md) guide.
- [ ] My code adheres to the project's Go style standards and conventions.
- [ ] All new and existing unit tests pass locally (`go test -v ./...`).
- [ ] I have added unit tests for new functionality, co-located in `*_test.go` adjacent to the code.
- [ ] If adding or changing Rego rules, I have run `treeguard test` and added corresponding test cases.
- [ ] I have run `go vet ./...` and `golangci-lint run` (if available) with zero issues reported.
- [ ] Documentation (README, docs, or rule metadata) has been updated accordingly.
