# 개발 명령 모음. 상세는 docs/development.md.
.PHONY: setup build build-wasm build-ext build-server test lint fmt fmt-check typecheck deny check clean

WASM_OUT := packages/extension/wasm

setup: ## 툴체인과 의존성 설치, git 훅 등록
	rustup target add wasm32-unknown-unknown
	cargo install wasm-pack cargo-deny --locked
	pnpm install
	pnpm exec lefthook install

build: build-wasm build-ext build-server ## 전체 빌드

build-wasm: ## mpc-core를 wasm으로 빌드해 확장에 넣는다
	wasm-pack build crates/mpc-wasm --target web --out-dir ../../$(WASM_OUT)
	@# 서비스 워커는 .wasm을 확장 URL로 가져오므로 public/에도 둔다.
	mkdir -p packages/extension/public/wasm
	cp $(WASM_OUT)/mpc_wasm_bg.wasm packages/extension/public/wasm/

build-ext: ## 크롬 확장 빌드
	pnpm -C packages/extension build

build-server: ## 서버 릴리스 빌드
	cargo build --release -p mpc-server

test: ## 전체 테스트
	cargo test --workspace
	pnpm -s test

lint: ## 린트 (경고를 에러로 취급)
	cargo clippy --workspace --all-targets -- -D warnings
	pnpm -s lint

fmt: ## 포매팅 적용
	cargo fmt --all
	pnpm -s fmt

fmt-check: ## 포매팅 검사
	cargo fmt --all --check
	pnpm -s fmt:check

typecheck: ## 타입 검사
	pnpm -s typecheck

deny: ## 라이선스·취약점 검사
	cargo deny check

check: fmt-check lint typecheck test ## 커밋 게이트. CI와 동일하다.
	@echo "OK"

clean:
	cargo clean
	rm -rf $(WASM_OUT) packages/extension/public/wasm packages/*/dist packages/*/.output packages/extension/.wxt
