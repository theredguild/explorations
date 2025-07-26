/**
 * Comprehensive test suite for DevContainer Wizard
 * Tests all possible combinations and validates generated configurations
 */

class WizardTester {
    constructor() {
        this.wizard = new DevContainerWizard();
        this.testResults = [];
        this.failedConfigs = [];
        
        // Define all possible options
        this.options = {
            security: ['minimal', 'secure', 'hardened', 'auditor'],
            shell: ['bash', 'zsh', 'fish'],
            tools: [
                [], // No tools
                ['solidity'],
                ['hardhat'],
                ['foundry'],
                ['vyper'],
                ['rust'],
                ['go'],
                ['nodejs'],
                ['python'],
                ['solidity', 'hardhat'],
                ['foundry', 'rust'],
                ['nodejs', 'python'],
                ['solidity', 'hardhat', 'foundry'], // Full Ethereum stack
                ['rust', 'go'], // Infrastructure languages
                ['solidity', 'vyper', 'python'] // All contract languages
            ],
            securityTools: [
                [], // No security tools
                ['fuzzing'],
                ['static-analysis'],
                ['symbolic-execution'],
                ['decompilers'],
                ['forensics'],
                ['fuzzing', 'static-analysis'],
                ['static-analysis', 'symbolic-execution'],
                ['fuzzing', 'static-analysis', 'symbolic-execution'], // Full security suite
                ['decompilers', 'forensics']
            ],
            features: [
                [], // No additional features
                ['git'],
                ['docker'],
                ['extensions'],
                ['ports'],
                ['asdf'],
                ['nvm'],
                ['package-managers'],
                ['ipfs'],
                ['git', 'extensions'], // Basic dev setup
                ['git', 'docker', 'extensions'], // Full dev setup
                ['asdf', 'package-managers'], // Version management
                ['git', 'extensions', 'ports', 'ipfs'] // Complete feature set
            ]
        };
    }

    // Generate test matrix with strategic sampling to avoid combinatorial explosion
    generateTestMatrix() {
        const testCases = [];
        
        // 1. Test each security profile with minimal config
        this.options.security.forEach(security => {
            testCases.push({
                security,
                shell: 'bash',
                tools: [],
                securityTools: [],
                features: []
            });
        });

        // 2. Test each shell with basic config
        this.options.shell.forEach(shell => {
            testCases.push({
                security: 'minimal',
                shell,
                tools: ['solidity'],
                securityTools: [],
                features: ['git']
            });
        });

        // 3. Test tool combinations with different security levels
        this.options.tools.forEach((tools, index) => {
            const securityLevel = this.options.security[index % this.options.security.length];
            testCases.push({
                security: securityLevel,
                shell: 'bash',
                tools,
                securityTools: [],
                features: ['git', 'extensions']
            });
        });

        // 4. Test security tool combinations
        this.options.securityTools.forEach((securityTools, index) => {
            const security = securityTools.length > 0 ? 'hardened' : 'minimal';
            testCases.push({
                security,
                shell: 'zsh',
                tools: ['solidity', 'foundry'],
                securityTools,
                features: ['git', 'extensions']
            });
        });

        // 5. Test feature combinations
        this.options.features.forEach((features, index) => {
            testCases.push({
                security: 'secure',
                shell: 'bash',
                tools: ['nodejs'],
                securityTools: [],
                features
            });
        });

        // 6. Add some complex realistic scenarios
        const realisticScenarios = [
            {
                name: 'Smart Contract Auditor',
                security: 'auditor',
                shell: 'zsh',
                tools: ['solidity', 'foundry'],
                securityTools: ['fuzzing', 'static-analysis', 'symbolic-execution'],
                features: ['git', 'extensions', 'asdf']
            },
            {
                name: 'Full Stack Web3 Developer',
                security: 'secure',
                shell: 'zsh',
                tools: ['solidity', 'hardhat', 'nodejs'],
                securityTools: ['static-analysis'],
                features: ['git', 'docker', 'extensions', 'ports', 'package-managers']
            },
            {
                name: 'Blockchain Infrastructure Developer',
                security: 'hardened',
                shell: 'fish',
                tools: ['rust', 'go'],
                securityTools: ['forensics'],
                features: ['git', 'docker', 'extensions', 'asdf']
            },
            {
                name: 'Multi-chain Developer',
                security: 'secure',
                shell: 'zsh',
                tools: ['solidity', 'rust', 'nodejs', 'python'],
                securityTools: ['static-analysis', 'fuzzing'],
                features: ['git', 'extensions', 'nvm', 'package-managers', 'ports', 'ipfs']
            }
        ];

        realisticScenarios.forEach(scenario => {
            testCases.push(scenario);
        });

        return testCases;
    }

    // Validate generated devcontainer.json structure
    validateDevContainer(config, generated) {
        const errors = [];

        // Basic structure validation
        if (!generated.name) errors.push('Missing name field');
        
        // Security validation
        if (config.security === 'hardened' || config.security === 'auditor') {
            if (!generated.runArgs || !generated.runArgs.includes('--security-opt=no-new-privileges')) {
                errors.push('Missing security hardening for hardened/auditor profile');
            }
        }

        // Features validation
        if (config.features.includes('git') && !generated.features?.['ghcr.io/devcontainers/features/git:1']) {
            errors.push('Git feature requested but not configured');
        }

        if (config.features.includes('docker') && !generated.features?.['ghcr.io/devcontainers/features/docker-in-docker:2']) {
            errors.push('Docker feature requested but not configured');
        }

        // Extension validation
        if (config.features.includes('extensions') && !generated.customizations?.vscode?.extensions) {
            errors.push('Extensions requested but not configured');
        }

        // Port validation
        if (config.features.includes('ports') && !generated.forwardPorts) {
            errors.push('Port forwarding requested but not configured');
        }

        return errors;
    }

    // Validate generated Dockerfile
    validateDockerfile(config, dockerfile) {
        const errors = [];

        if (!dockerfile) {
            if (this.shouldHaveDockerfile(config)) {
                errors.push('Dockerfile should be generated but is missing');
            }
            return errors;
        }

        // Check for proper base image
        if (!dockerfile.includes('FROM ')) {
            errors.push('Missing FROM instruction');
        }

        // Security validation
        if (config.security === 'hardened' || config.security === 'auditor') {
            if (!dockerfile.includes('groupadd -r devuser')) {
                errors.push('Missing security user setup for hardened profile');
            }
        }

        // Tool validation
        config.tools.forEach(tool => {
            if (!this.dockerfileContainsTool(dockerfile, tool)) {
                errors.push(`Tool ${tool} requested but not found in Dockerfile`);
            }
        });

        // Security tools validation
        config.securityTools.forEach(toolGroup => {
            if (!this.dockerfileContainsSecurityTool(dockerfile, toolGroup)) {
                errors.push(`Security tool group ${toolGroup} requested but not found in Dockerfile`);
            }
        });

        // Shell validation
        if (config.shell === 'zsh' && !dockerfile.includes('zsh')) {
            errors.push('Zsh shell requested but not installed');
        }
        if (config.shell === 'fish' && !dockerfile.includes('fish')) {
            errors.push('Fish shell requested but not installed');
        }

        return errors;
    }

    shouldHaveDockerfile(config) {
        return config.security === 'hardened' || 
               config.security === 'auditor' ||
               config.securityTools.length > 0 ||
               config.tools.length > 1 ||
               config.shell !== 'bash' ||
               config.tools.includes('foundry') ||
               config.tools.includes('solidity') ||
               config.tools.includes('vyper') ||
               config.features.includes('package-managers');
    }

    dockerfileContainsTool(dockerfile, tool) {
        const patterns = {
            solidity: /solc-select|solidity/i,
            hardhat: /hardhat/i,
            foundry: /foundry|forge/i,
            vyper: /vyper/i,
            rust: /rust|cargo/i,
            go: /golang|go\d/i,
            nodejs: /node|npm/i,
            python: /python3|pip3/i
        };

        return patterns[tool]?.test(dockerfile) || false;
    }

    dockerfileContainsSecurityTool(dockerfile, toolGroup) {
        const patterns = {
            'fuzzing': /medusa|echidna|ityfuzz/i,
            'static-analysis': /slither|semgrep|aderyn/i,
            'symbolic-execution': /mythril|halmos/i,
            'decompilers': /panoramix|heimdall/i,
            'forensics': /napalm|hexdump/i
        };

        return patterns[toolGroup]?.test(dockerfile) || false;
    }

    // Run a single test case
    async runTestCase(testCase, index) {
        try {
            const config = {
                security: testCase.security,
                shell: testCase.shell,
                tools: testCase.tools,
                securityTools: testCase.securityTools,
                features: testCase.features
            };

            // Generate configurations
            const devcontainerConfig = this.wizard.buildDevContainerConfig(config);
            const dockerfile = this.wizard.buildDockerfile(config);

            // Validate
            const devcontainerErrors = this.validateDevContainer(config, devcontainerConfig);
            const dockerfileErrors = this.validateDockerfile(config, dockerfile);

            const allErrors = [...devcontainerErrors, ...dockerfileErrors];

            const result = {
                index,
                config,
                name: testCase.name || `Test Case ${index + 1}`,
                passed: allErrors.length === 0,
                errors: allErrors,
                devcontainerConfig,
                dockerfile: dockerfile || null
            };

            if (!result.passed) {
                this.failedConfigs.push(result);
            }

            this.testResults.push(result);
            return result;

        } catch (error) {
            const result = {
                index,
                config: testCase,
                name: testCase.name || `Test Case ${index + 1}`,
                passed: false,
                errors: [`Exception thrown: ${error.message}`],
                exception: error
            };

            this.failedConfigs.push(result);
            this.testResults.push(result);
            return result;
        }
    }

    // Run all tests
    async runAllTests() {
        console.log('🧪 Starting DevContainer Wizard Test Suite...');
        
        const testCases = this.generateTestMatrix();
        console.log(`📋 Generated ${testCases.length} test cases`);

        this.testResults = [];
        this.failedConfigs = [];

        // Run tests with progress reporting
        for (let i = 0; i < testCases.length; i++) {
            const result = await this.runTestCase(testCases[i], i);
            
            if (i % 10 === 0) {
                console.log(`⏳ Progress: ${i + 1}/${testCases.length} tests completed`);
            }
        }

        return this.generateReport();
    }

    // Generate comprehensive test report
    generateReport() {
        const totalTests = this.testResults.length;
        const passedTests = this.testResults.filter(t => t.passed).length;
        const failedTests = totalTests - passedTests;

        const report = {
            summary: {
                total: totalTests,
                passed: passedTests,
                failed: failedTests,
                passRate: ((passedTests / totalTests) * 100).toFixed(1) + '%'
            },
            failedTests: this.failedConfigs.map(test => ({
                name: test.name,
                config: test.config,
                errors: test.errors
            })),
            categoryBreakdown: this.generateCategoryBreakdown(),
            recommendations: this.generateRecommendations()
        };

        return report;
    }

    generateCategoryBreakdown() {
        const breakdown = {
            bySecurityProfile: {},
            byShell: {},
            byToolCount: {},
            bySecurityToolCount: {}
        };

        this.testResults.forEach(result => {
            const config = result.config;

            // By security profile
            if (!breakdown.bySecurityProfile[config.security]) {
                breakdown.bySecurityProfile[config.security] = { total: 0, passed: 0 };
            }
            breakdown.bySecurityProfile[config.security].total++;
            if (result.passed) breakdown.bySecurityProfile[config.security].passed++;

            // By shell
            if (!breakdown.byShell[config.shell]) {
                breakdown.byShell[config.shell] = { total: 0, passed: 0 };
            }
            breakdown.byShell[config.shell].total++;
            if (result.passed) breakdown.byShell[config.shell].passed++;

            // By tool count
            const toolCount = config.tools.length;
            if (!breakdown.byToolCount[toolCount]) {
                breakdown.byToolCount[toolCount] = { total: 0, passed: 0 };
            }
            breakdown.byToolCount[toolCount].total++;
            if (result.passed) breakdown.byToolCount[toolCount].passed++;

            // By security tool count
            const secToolCount = config.securityTools.length;
            if (!breakdown.bySecurityToolCount[secToolCount]) {
                breakdown.bySecurityToolCount[secToolCount] = { total: 0, passed: 0 };
            }
            breakdown.bySecurityToolCount[secToolCount].total++;
            if (result.passed) breakdown.bySecurityToolCount[secToolCount].passed++;
        });

        return breakdown;
    }

    generateRecommendations() {
        const recommendations = [];
        
        if (this.failedConfigs.length > 0) {
            const commonErrors = {};
            this.failedConfigs.forEach(config => {
                config.errors.forEach(error => {
                    commonErrors[error] = (commonErrors[error] || 0) + 1;
                });
            });

            const sortedErrors = Object.entries(commonErrors)
                .sort(([,a], [,b]) => b - a)
                .slice(0, 5);

            recommendations.push('🔧 Most common issues to fix:');
            sortedErrors.forEach(([error, count]) => {
                recommendations.push(`   • ${error} (${count} occurrences)`);
            });
        }

        return recommendations;
    }

    // Generate HTML report
    generateHTMLReport(report) {
        return `
<!DOCTYPE html>
<html>
<head>
    <title>DevContainer Wizard Test Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .summary { background: #f0f8ff; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .pass { color: #28a745; }
        .fail { color: #dc3545; }
        .breakdown { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
        .category { background: #f8f9fa; padding: 15px; border-radius: 5px; }
        .failed-test { background: #fff5f5; border-left: 4px solid #dc3545; padding: 10px; margin: 10px 0; }
        .config { background: #f8f8f8; padding: 8px; border-radius: 3px; font-family: monospace; }
        pre { background: #f8f8f8; padding: 10px; overflow-x: auto; }
    </style>
</head>
<body>
    <h1>🧪 DevContainer Wizard Test Report</h1>
    
    <div class="summary">
        <h2>📊 Test Summary</h2>
        <p><strong>Total Tests:</strong> ${report.summary.total}</p>
        <p><strong class="pass">Passed:</strong> ${report.summary.passed}</p>
        <p><strong class="fail">Failed:</strong> ${report.summary.failed}</p>
        <p><strong>Pass Rate:</strong> ${report.summary.passRate}</p>
    </div>

    <div class="breakdown">
        <div class="category">
            <h3>By Security Profile</h3>
            ${Object.entries(report.categoryBreakdown.bySecurityProfile)
                .map(([profile, stats]) => 
                    `<p>${profile}: ${stats.passed}/${stats.total} (${((stats.passed/stats.total)*100).toFixed(1)}%)</p>`
                ).join('')}
        </div>
        
        <div class="category">
            <h3>By Shell</h3>
            ${Object.entries(report.categoryBreakdown.byShell)
                .map(([shell, stats]) => 
                    `<p>${shell}: ${stats.passed}/${stats.total} (${((stats.passed/stats.total)*100).toFixed(1)}%)</p>`
                ).join('')}
        </div>
        
        <div class="category">
            <h3>By Tool Count</h3>
            ${Object.entries(report.categoryBreakdown.byToolCount)
                .map(([count, stats]) => 
                    `<p>${count} tools: ${stats.passed}/${stats.total} (${((stats.passed/stats.total)*100).toFixed(1)}%)</p>`
                ).join('')}
        </div>
    </div>

    ${report.failedTests.length > 0 ? `
    <h2>❌ Failed Tests</h2>
    ${report.failedTests.map(test => `
        <div class="failed-test">
            <h4>${test.name}</h4>
            <div class="config">
                <strong>Config:</strong> ${JSON.stringify(test.config, null, 2)}
            </div>
            <p><strong>Errors:</strong></p>
            <ul>
                ${test.errors.map(error => `<li>${error}</li>`).join('')}
            </ul>
        </div>
    `).join('')}
    ` : '<h2 class="pass">✅ All Tests Passed!</h2>'}

    <h2>💡 Recommendations</h2>
    <ul>
        ${report.recommendations.map(rec => `<li>${rec.replace(/^🔧|•/, '')}</li>`).join('')}
    </ul>
</body>
</html>`;
    }
}

// Export for use
if (typeof module !== 'undefined' && module.exports) {
    module.exports = WizardTester;
}