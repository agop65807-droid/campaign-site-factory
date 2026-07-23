const fs = require('fs');
const path = require('path');
const https = require('https');
const crypto = require('crypto');

const TOKEN = process.env.VERCEL_TOKEN;
const TEAM_ID = process.env.VERCEL_TEAM_ID;
const PROJECT_NAME = process.env.VERCEL_PROJECT_NAME || 'campaign-site-factory';

if (!TOKEN || !TEAM_ID) {
  throw new Error('VERCEL_TOKEN and VERCEL_TEAM_ID must be set before deploying');
}

function apiCall(method, apiPath, body, isBinary = false) {
  return new Promise((resolve, reject) => {
    let data;
    if (body) {
      data = isBinary ? body : JSON.stringify(body);
    }
    const headers = {
      'Authorization': `Bearer ${TOKEN}`,
    };
    if (!isBinary) headers['Content-Type'] = 'application/json';
    else headers['Content-Type'] = 'application/octet-stream';
    if (data) headers['Content-Length'] = Buffer.byteLength(data);

    const options = {
      hostname: 'api.vercel.com',
      path: apiPath,
      method: method,
      headers: headers
    };

    const req = https.request(options, (res) => {
      let chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        const buf = Buffer.concat(chunks);
        const str = buf.toString();
        try { resolve({ status: res.statusCode, data: JSON.parse(str), headers: res.headers }); }
        catch { resolve({ status: res.statusCode, data: str, headers: res.headers }); }
      });
    });
    req.on('error', reject);
    if (data) req.write(data);
    req.end();
  });
}

async function deploy() {
  console.log('Uploading files...');

  const files = [];
  const baseDir = __dirname;
  const skipDirs = ['node_modules', '.git', '.vercel', '.env'];

  function walkDir(dir, relPath = '') {
    const items = fs.readdirSync(dir);
    for (const item of items) {
      if (skipDirs.includes(item)) continue;
      const fullPath = path.join(dir, item);
      const rel = relPath ? `${relPath}/${item}` : item;
      const stat = fs.statSync(fullPath);
      if (stat.isDirectory()) {
        walkDir(fullPath, rel);
      } else {
        files.push({ path: rel, fullPath });
      }
    }
  }
  
  walkDir(baseDir);
  console.log(`Found ${files.length} files`);

  // Upload files
  const fileMap = [];
  for (const file of files) {
    const content = fs.readFileSync(file.fullPath);
    const hash = crypto.createHash('sha1').update(content).digest('hex');

    // Upload with proper headers
    const uploadResp = await new Promise((resolve, reject) => {
      const req = https.request({
        hostname: 'api.vercel.com',
        path: `/v2/files?teamId=${TEAM_ID}`,
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${TOKEN}`,
          'Content-Type': 'application/octet-stream',
          'Content-Length': content.length,
          'x-vercel-digest': hash
        }
      }, (res) => {
        let chunks = [];
        res.on('data', c => chunks.push(c));
        res.on('end', () => {
          const str = Buffer.concat(chunks).toString();
          try { resolve({ status: res.statusCode, data: JSON.parse(str) }); }
          catch { resolve({ status: res.statusCode, data: str }); }
        });
      });
      req.on('error', reject);
      req.write(content);
      req.end();
    });

    if (uploadResp.status === 200) {
      console.log(`  OK: ${file.path}`);
    } else {
      console.log(`  WARN: ${file.path} (${uploadResp.status})`);
    }
    fileMap.push({ file: file.path, sha: hash, size: content.length });
  }

  console.log('\nCreating deployment...');
  const deployResp = await apiCall('POST', `/v13/deployments?teamId=${TEAM_ID}&skipBuildDetection=1`, {
    name: PROJECT_NAME,
    target: 'production',
    projectSettings: {
      framework: null,
      buildCommand: null,
      outputDirectory: '.',
      installCommand: 'npm install --production',
      devCommand: null
    },
    files: fileMap.map(f => ({ file: f.file, sha: f.sha, size: f.size }))
  });

  if (deployResp.status === 200 || deployResp.status === 201) {
    const url = deployResp.data.url;
    const deploymentId = deployResp.data.id;
    console.log(`\n✅ Deployment created successfully!`);
    console.log(`URL: https://${url}`);
    console.log(`Deployment ID: ${deploymentId}`);

    console.log('\nWaiting for build to complete...');
    let ready = false;
    let attempts = 0;
    while (!ready && attempts < 60) {
      await new Promise(r => setTimeout(r, 5000));
      attempts++;
      const statusResp = await apiCall('GET', `/v13/deployments/${deploymentId}?teamId=${TEAM_ID}`);
      if (statusResp.data.readyState === 'READY') {
        ready = true;
        console.log(`\n🎉 BUILD COMPLETE!`);
        console.log(`Production URL: https://${statusResp.data.url}`);
        if (statusResp.data.alias) {
          console.log(`Aliases: ${statusResp.data.alias.join(', ')}`);
        }
      } else if (statusResp.data.readyState === 'ERROR') {
        console.log(`\n❌ Build failed!`);
        console.log(JSON.stringify(statusResp.data, null, 2).substring(0, 1000));
        break;
      } else {
        process.stdout.write('.');
      }
    }
  } else {
    console.error('Deploy failed:', deployResp.status, JSON.stringify(deployResp.data).substring(0, 500));
  }
}

deploy().catch(e => console.error('Error:', e.message));
