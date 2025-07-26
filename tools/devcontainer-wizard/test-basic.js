const DevContainerWizard = require('./wizard.js');

console.log('🧪 Testing fixed wizard functionality...');

// Create mock wizard instance  
const wizard = {
  buildDevContainerConfig: DevContainerWizard.prototype.buildDevContainerConfig,
  buildDockerfile: DevContainerWizard.prototype.buildDockerfile,
  getToolInstallation: DevContainerWizard.prototype.getToolInstallation,
  getSecurityToolInstallation: DevContainerWizard.prototype.getSecurityToolInstallation,
  getPackageManagerInstallation: DevContainerWizard.prototype.getPackageManagerInstallation,
  getIPFSInstallation: DevContainerWizard.prototype.getIPFSInstallation,
  getRecommendedExtensions: DevContainerWizard.prototype.getRecommendedExtensions,
  getCommonPorts: DevContainerWizard.prototype.getCommonPorts,
  getShellPath: DevContainerWizard.prototype.getShellPath,
  getPostCreateCommand: DevContainerWizard.prototype.getPostCreateCommand,
  needsCustomDockerfile: DevContainerWizard.prototype.needsCustomDockerfile,
  getPredefinedImage: DevContainerWizard.prototype.getPredefinedImage
};

console.log('✅ All methods loaded successfully');

// Test configurations
const testConfigs = [
  {
    name: 'Basic Solidity',
    config: {
      security: 'minimal',
      shell: 'bash',
      tools: ['solidity'],
      securityTools: [],
      features: ['git']
    }
  },
  {
    name: 'IPFS + Ports',
    config: {
      security: 'minimal',
      shell: 'bash',
      tools: [],
      securityTools: [],
      features: ['ipfs', 'ports']
    }
  },
  {
    name: 'Full Security Stack',
    config: {
      security: 'hardened',
      shell: 'zsh',
      tools: ['solidity', 'foundry'],
      securityTools: ['static-analysis', 'fuzzing'],
      features: ['git', 'extensions']
    }
  }
];

let allPassed = true;

testConfigs.forEach(test => {
  try {
    console.log(`\n🔬 Testing: ${test.name}`);
    
    const devcontainer = wizard.buildDevContainerConfig.call(wizard, test.config);
    const dockerfile = wizard.buildDockerfile.call(wizard, test.config);
    
    console.log('  ✅ DevContainer config generated');
    console.log('  ✅ Dockerfile generated');
    
    // Basic validation
    if (!devcontainer.name) {
      throw new Error('Missing devcontainer name');
    }
    
    if (test.config.features.includes('ipfs') && dockerfile && !dockerfile.includes('ipfs')) {
      throw new Error('IPFS not found in Dockerfile');
    }
    
    if (test.config.features.includes('ports') && !devcontainer.forwardPorts) {
      throw new Error('Ports not configured');
    }
    
    console.log('  ✅ Validation passed');
    
  } catch (error) {
    console.log(`  ❌ Error: ${error.message}`);
    allPassed = false;
  }
});

console.log(`\n${allPassed ? '🎉 All tests passed!' : '❌ Some tests failed'}`);