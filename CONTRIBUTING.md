# Contributing to Keygen Provider

Welcome! We're excited that you're interested in contributing to the Keygen provider for Pulumi.

## Getting Started

1. Fork the repository
2. Clone your fork locally
3. Create a new branch for your feature or bug fix
4. Make your changes
5. Commit your changes with a clear commit message
6. Push your changes to your fork
7. Open a pull request

## Development Setup

To set up your development environment:

1. Install Go (version 1.21 or later)
2. Install Pulumi CLI
3. Run `make build` to build the provider

## Building

Use the provided Makefile for common tasks:

- `make build` - Build the provider binary
- `make install` - Install the provider locally
- `make schema` - Generate the schema.json file
- `make test` - Run tests

## Testing

Run tests with:

```bash
make test
```

## Releasing

Releases are managed via GitHub Actions. To create a new release:

1. Update the version in schema.json
2. Create a new git tag (e.g., `v1.2.3`)
3. Push the tag to GitHub
4. The release workflow will automatically create binaries and GitHub release

## Code Style

Follow standard Go conventions and idioms. Run `gofmt` on your code before submitting.

## Reporting Issues

Please report bugs and feature requests via GitHub issues.