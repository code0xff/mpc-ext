# Development commands. Details in docs/development.md.
.PHONY: setup build build-wasm build-ext build-server test lint fmt fmt-check typecheck deny openapi check clean

WASM_OUT := packages/extension/wasm

setup: ## Install toolchains and dependencies, register git hooks
	rustup target add wasm32-unknown-unknown
	cargo install wasm-pack cargo-deny --locked
	pnpm install
	pnpm exec lefthook install

build: build-wasm build-ext build-server ## Build everything

build-wasm: ## Build mpc-core to wasm and place it in the extension
	wasm-pack build crates/mpc-wasm --target web --out-dir ../../$(WASM_OUT)
	@# The service worker fetches the .wasm over an extension URL, so it also lives in public/.
	mkdir -p packages/extension/public/wasm
	cp $(WASM_OUT)/mpc_wasm_bg.wasm packages/extension/public/wasm/

build-ext: ## Build the Chrome extension
	pnpm -C packages/extension build

build-server: ## Build the server in release mode
	cargo build --release -p mpc-server

test: ## Run every test
	cargo test --workspace
	pnpm -s test

lint: ## Lint, treating warnings as errors
	cargo clippy --workspace --all-targets -- -D warnings
	pnpm -s lint

fmt: ## Apply formatting
	cargo fmt --all
	pnpm -s fmt

fmt-check: ## Check formatting
	cargo fmt --all --check
	pnpm -s fmt:check

typecheck: ## Type-check
	pnpm -s typecheck

openapi: ## Regenerate docs/openapi.json from the server code
	cargo run -q -p mpc-server --example openapi

deny: ## Check licences and advisories
	cargo deny check

check: fmt-check lint typecheck test ## The commit gate. Identical to CI.
	@echo "OK"

clean:
	cargo clean
	rm -rf $(WASM_OUT) packages/extension/public/wasm packages/*/dist packages/*/.output packages/extension/.wxt
