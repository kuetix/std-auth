#!/bin/bash
# Runner script for http
# This script automatically generates module cache and runs/tests the application

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored messages
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "\033[0;31m[ERROR]\033[0m $1"
}

# Check if kue is installed
if ! command -v kue &> /dev/null; then
    print_warn "kue command not found. Please install it first:"
    echo "  go install github.com/kuetix/engine/cmd/kue@latest"
    exit 1
fi

# Parse command line arguments
COMMAND=${1:-"help"}

case "$COMMAND" in
    run)
        print_info "Running application..."
        
        # Check if workflow argument is provided
        if [ -z "$2" ]; then
            print_warn "Usage: ./runner.sh run <workflow> [args...]"
            echo "Example: ./runner.sh run workflows/common/example.wsl"
            exit 1
        fi
        
        WORKFLOW="$2"
        shift 2
        
        print_info "Workflow: $WORKFLOW"
        if kue run "$WORKFLOW" "$@"; then
            print_success "Workflow execution completed"
        else
            print_error "Workflow execution failed"
            exit 1
        fi
        ;;
        
    test)
        print_info "Testing all workflows, features, and solutions..."
        
        FAILED_COUNT=0
        PASSED_COUNT=0
        
        # Test workflows
        if [ -d "workflows/common" ] && [ "$(ls -A workflows/common/*.wsl 2>/dev/null)" ]; then
            print_info "Testing workflows..."
            for workflow in workflows/common/*.wsl; do
                [ -f "$workflow" ] || continue
                print_info "  Testing: $workflow"
                if kue run --quiet "$workflow" 2>&1 >/dev/null; then
                    print_success "  ✓ $workflow"
                    ((PASSED_COUNT++))
                else
                    print_warn "  ✗ $workflow failed"
                    ((FAILED_COUNT++))
                fi
            done
        fi
        
        # Test features
        if [ -d "workflows/features" ] && [ "$(ls -A workflows/features/*.wsl 2>/dev/null)" ]; then
            print_info "Testing features..."
            for feature in workflows/features/*.wsl; do
                [ -f "$feature" ] || continue
                print_info "  Testing: $feature"
                if kue run --quiet "$feature" 2>&1 >/dev/null; then
                    print_success "  ✓ $feature"
                    ((PASSED_COUNT++))
                else
                    print_warn "  ✗ $feature failed"
                    ((FAILED_COUNT++))
                fi
            done
        fi
        
        # Test solutions
        if [ -d "workflows/solutions" ] && [ "$(ls -A workflows/solutions/*.wsl 2>/dev/null)" ]; then
            print_info "Testing solutions..."
            for solution in workflows/solutions/*.wsl; do
                [ -f "$solution" ] || continue
                print_info "  Testing: $solution"
                if kue run --quiet "$solution" 2>&1 >/dev/null; then
                    print_success "  ✓ $solution"
                    ((PASSED_COUNT++))
                else
                    print_warn "  ✗ $solution failed"
                    ((FAILED_COUNT++))
                fi
            done
        fi
        
        # Run kue test if tests directory exists
        if [ -d "tests" ]; then
            print_info "Running test suite..."
            if kue test; then
                print_success "Test suite passed"
            else
                print_warn "Test suite had failures"
                ((FAILED_COUNT++))
            fi
        fi
        
        # Print summary
        echo ""
        print_info "Test Summary: $PASSED_COUNT passed, $FAILED_COUNT failed"
        
        if [ $FAILED_COUNT -gt 0 ]; then
            print_error "Some tests failed"
            exit 1
        else
            print_success "All tests passed"
        fi
        ;;
        
    validate)
        print_info "Validating all workflows..."
        
        FAILED_COUNT=0
        
        # Use find to locate all workflow files
        while IFS= read -r -d '' workflow; do
            print_info "  Validating: $workflow"
            if kue validate --file "$workflow"; then
                print_success "  ✓ $workflow"
            else
                print_warn "  ✗ $workflow failed"
                ((FAILED_COUNT++))
            fi
        done < <(find workflows -type f \( -name "*.wsl" -o -name "*.swsl" \) -print0 2>/dev/null)
        
        echo ""
        if [ $FAILED_COUNT -gt 0 ]; then
            print_error "Validation failed for $FAILED_COUNT file(s)"
            exit 1
        else
            print_success "Validation completed successfully"
        fi
        ;;
        
    build)
        print_info "Building application..."
        
        if [ -f "Makefile" ]; then
            if make all; then
                print_success "Build completed. Binaries are in runtime/bin/"
            else
                print_error "Build failed"
                exit 1
            fi
        else
            print_warn "No Makefile found"
            exit 1
        fi
        ;;
        
    clean)
        print_info "Cleaning generated files..."
        
        # Remove generated cache files
        rm -f modules/di.go modules/meta.go modules.json
        
        # Remove built binaries
        if [ -d "runtime/bin" ]; then
            rm -rf runtime/bin/*
        fi
        
        # Clean logs
        if [ -d "runtime/log" ]; then
            rm -f runtime/log/*.log
        fi
        
        print_success "Cleanup completed"
        ;;
        
    help|--help|-h)
        echo "Runner script for http"
        echo ""
        echo "Usage: ./runner.sh <command> [options]"
        echo ""
        echo "Commands:"
        echo "  run <workflow> [args]  Run a specific workflow"
        echo "  test                   Test all workflows, features, and solutions"
        echo "  validate               Validate all workflow files"
        echo "  build                  Build the application"
        echo "  clean                  Clean generated files and build artifacts"
        echo "  help                   Show this help message"
        echo ""
        echo "Examples:"
        echo "  ./runner.sh run workflows/common/example.wsl"
        echo "  ./runner.sh test"
        echo "  ./runner.sh validate"
        echo "  ./runner.sh build"
        echo ""
        echo "Note: Module cache (di.go, meta.go, modules.json) is automatically"
        echo "      generated by kue run command, so no manual kueinit is needed."
        ;;
        
    *)
        print_warn "Unknown command: $COMMAND"
        echo "Run './runner.sh help' for usage information"
        exit 1
        ;;
esac
