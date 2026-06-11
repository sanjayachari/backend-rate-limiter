// spam_test.js
// Run: node spam_test.js

const BASE_URL = "http://localhost:3000";

async function spamLoop() {
  console.log("🤖 Starting spam loop on /api/create-record...\n");

  let allowed = 0;
  let blocked = 0;

  for (let i = 1; i <= 20; i++) {
    const res = await fetch(`${BASE_URL}/api/create-record`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        name: `spammer_${i}`,
        email: `fake${i}@spam.com`,
        message: "looping this endpoint",
      }),
    });

    const data = await res.json();

    if (res.status === 429) {
      blocked++;
      console.log(`  #${String(i).padStart(2,"0")} → 🚫 ${res.status} BLOCKED  | ${data.error}`);
    } else {
      allowed++;
      console.log(`  #${String(i).padStart(2,"0")} → ✅ ${res.status} ALLOWED  | requestId: ${data.requestId}`);
    }
  }

  console.log(`\n📊 Result: ${allowed} allowed, ${blocked} blocked`);
}

spamLoop();