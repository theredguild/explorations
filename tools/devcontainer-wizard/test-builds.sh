#!/bin/bash

# DevContainer Build Test Script
# Tests actual devcontainer builds for common configurations

set -e

echo "🐳 DevContainer Build Test Suite"
echo "================================="

# Create test directory
TEST_DIR="./test-builds"
mkdir -p "$TEST_DIR"

# Test configurations to validate
declare -A TEST_CONFIGS=(
    ["minimal"]='{"security":"minimal","shell":"bash","tools":[],"securityTools":[],"features":[]}'
    ["basic-solidity"]='{"security":"minimal","shell":"bash","tools":["solidity","foundry"],"securityTools":[],"features":["git","extensions"]}'
    ["security-auditor"]='{"security":"auditor","shell":"zsh","tools":["solidity"],"securityTools":["static-analysis","fuzzing"],"features":["git","extensions"]}'
    ["web3-dev"]='{"security":"secure","shell":"zsh","tools":["solidity","hardhat","nodejs"],"securityTools":["static-analysis"],"features":["git","docker","extensions","ports"]}'
    ["hardened"]='{"security":"hardened","shell":"bash","tools":["solidity"],"securityTools":["static-analysis"],"features":["git"]}'
)

# Function to generate devcontainer files from config
generate_devcontainer() {
    local config_name="$1"
    local config_json="$2"
    local test_path="$TEST_DIR/$config_name"
    
    echo "📋 Generating $config_name configuration..."
    
    mkdir -p "$test_path/.devcontainer"
    
    # Use Node.js to generate the files (requires the wizard to be available)
    node -e "
        const fs = require('fs');
        const { DevContainerWizard } = require('../wizard.js');
        
        const wizard = new DevContainerWizard();
        const config = JSON.parse('$config_json');
        
        const devcontainerConfig = wizard.buildDevContainerConfig(config);
        const dockerfile = wizard.buildDockerfile(config);
        
        fs.writeFileSync('$test_path/.devcontainer/devcontainer.json', JSON.stringify(devcontainerConfig, null, 2));
        
        if (dockerfile) {
            fs.writeFileSync('$test_path/.devcontainer/Dockerfile', dockerfile);
        }
        
        console.log('Generated files for $config_name');
    " 2>/dev/null || {
        echo "⚠️  Could not generate $config_name (Node.js/wizard dependency issue)"
        return 1
    }
}

# Function to test devcontainer build
test_build() {
    local config_name="$1"
    local test_path="$TEST_DIR/$config_name"
    
    echo "🔨 Testing build for $config_name..."
    
    if [ ! -f "$test_path/.devcontainer/devcontainer.json" ]; then
        echo "❌ No devcontainer.json found for $config_name"
        return 1
    fi
    
    cd "$test_path"
    
    # Try to build the devcontainer
    if command -v devcontainer &> /dev/null; then
        echo "   Using devcontainer CLI..."
        if timeout 300 devcontainer build --workspace-folder . --log-level info; then
            echo "✅ $config_name: Build successful"
            return 0
        else
            echo "❌ $config_name: Build failed"
            return 1
        fi
    elif command -v docker &> /dev/null; then
        echo "   Using Docker directly..."
        
        # Extract image or dockerfile info
        if [ -f ".devcontainer/Dockerfile" ]; then
            if timeout 300 docker build -f .devcontainer/Dockerfile -t "test-$config_name" .; then
                echo "✅ $config_name: Docker build successful"
                docker rmi "test-$config_name" 2>/dev/null || true
                return 0
            else
                echo "❌ $config_name: Docker build failed"
                return 1
            fi
        else
            # Try to pull the base image specified in devcontainer.json
            local image=$(grep -o '"image"[[:space:]]*:[[:space:]]*"[^"]*"' .devcontainer/devcontainer.json | cut -d'"' -f4)
            if [ -n "$image" ]; then
                if docker pull "$image"; then
                    echo "✅ $config_name: Base image available"
                    return 0
                else
                    echo "❌ $config_name: Base image unavailable"
                    return 1
                fi
            else
                echo "⚠️  $config_name: No build method available"
                return 2
            fi
        fi
    else
        echo "⚠️  No Docker or devcontainer CLI available - skipping build test"
        return 2
    fi
    
    cd - > /dev/null
}

# Function to validate generated files
validate_files() {
    local config_name="$1"
    local test_path="$TEST_DIR/$config_name"
    
    echo "🔍 Validating files for $config_name..."
    
    local errors=0
    
    # Check devcontainer.json syntax
    if ! python3 -m json.tool "$test_path/.devcontainer/devcontainer.json" > /dev/null 2>&1; then
        echo "❌ Invalid JSON in devcontainer.json"
        ((errors++))
    fi
    
    # Check Dockerfile syntax if it exists
    if [ -f "$test_path/.devcontainer/Dockerfile" ]; then
        if ! grep -q "^FROM " "$test_path/.devcontainer/Dockerfile"; then
            echo "❌ Dockerfile missing FROM instruction"
            ((errors++))
        fi
        
        # Check for common issues
        if grep -q "apt-get update" "$test_path/.devcontainer/Dockerfile" && ! grep -q "rm -rf /var/lib/apt/lists" "$test_path/.devcontainer/Dockerfile"; then
            echo "⚠️  Dockerfile may not clean apt cache"
        fi
    fi
    
    if [ $errors -eq 0 ]; then
        echo "✅ $config_name: File validation passed"
        return 0
    else
        echo "❌ $config_name: File validation failed ($errors errors)"
        return 1
    fi
}

# Main test execution
main() {
    local total_tests=0
    local passed_tests=0
    local failed_tests=0
    local skipped_tests=0
    
    echo ""
    echo "Phase 1: Generating test configurations"
    echo "======================================"
    
    for config_name in "${!TEST_CONFIGS[@]}"; do
        if generate_devcontainer "$config_name" "${TEST_CONFIGS[$config_name]}"; then
            echo "✅ Generated $config_name"
        else
            echo "❌ Failed to generate $config_name"
        fi
    done
    
    echo ""
    echo "Phase 2: File validation"
    echo "======================="
    
    for config_name in "${!TEST_CONFIGS[@]}"; do
        ((total_tests++))
        if validate_files "$config_name"; then
            ((passed_tests++))
        else
            ((failed_tests++))
        fi
    done
    
    echo ""
    echo "Phase 3: Build testing (if Docker available)"
    echo "==========================================="
    
    for config_name in "${!TEST_CONFIGS[@]}"; do
        ((total_tests++))
        result=$(test_build "$config_name")
        case $? in
            0) ((passed_tests++)) ;;
            1) ((failed_tests++)) ;;
            2) ((skipped_tests++)) ;;
        esac
    done
    
    echo ""
    echo "📊 Test Results Summary"
    echo "======================"
    echo "Total tests: $total_tests"
    echo "Passed: $passed_tests"
    echo "Failed: $failed_tests"
    echo "Skipped: $skipped_tests"
    echo "Pass rate: $(( passed_tests * 100 / (total_tests - skipped_tests) ))%"
    
    if [ $failed_tests -eq 0 ]; then
        echo "🎉 All tests passed!"
        exit 0
    else
        echo "❌ Some tests failed"
        exit 1
    fi
}

# Check prerequisites
check_prerequisites() {
    echo "🔧 Checking prerequisites..."
    
    local missing_deps=0
    
    if ! command -v python3 &> /dev/null; then
        echo "❌ python3 not found (needed for JSON validation)"
        ((missing_deps++))
    fi
    
    if ! command -v node &> /dev/null; then
        echo "⚠️  node not found (needed for file generation)"
        echo "   Will attempt to use pre-generated test files"
    fi
    
    if ! command -v docker &> /dev/null && ! command -v devcontainer &> /dev/null; then
        echo "⚠️  Neither docker nor devcontainer CLI found"
        echo "   Build tests will be skipped"
    fi
    
    if [ $missing_deps -gt 0 ]; then
        echo "❌ Missing required dependencies"
        exit 1
    fi
    
    echo "✅ Prerequisites check passed"
}

# Cleanup function
cleanup() {
    echo ""
    echo "🧹 Cleaning up test files..."
    rm -rf "$TEST_DIR"
    echo "✅ Cleanup completed"
}

# Set up signal handlers
trap cleanup EXIT

# Run the tests
check_prerequisites
main

echo ""
echo "🏁 Build test suite completed!"