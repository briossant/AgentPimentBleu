---
Video Script: AgentPimentBleu
---

**SCENE 1: INTRO & PROBLEM**

**(MUSIC: Upbeat, slightly techy, intro music - fades after ~5 seconds)**

**VOICEOVER (Friendly, Enthusiastic):**
Hi everyone! Ever feel like you're drowning in security alerts for your projects? You want to keep your code safe, but sometimes it’s just... too much. Today, I want to talk about tackling that information overload, especially for developers juggling multiple projects.

**(VISUAL CUE: [Screen showing a stylized, slightly overwhelming dashboard of alerts or many browser tabs with GitHub notifications])**

---

**SCENE 2: MEET ERWAN - THE PAIN POINT**

**VOICEOVER:**
Meet Erwan. Erwan is a passionate developer, always tinkering with personal projects, building cool new things. Like many of us, Erwan uses tools like GitHub's Dependabot to stay on top of security vulnerabilities in project dependencies.

**(VISUAL CUE: [Simple animation or graphic of a developer avatar "Erwan" looking happy, then show a GitHub Dependabot email notification popping up. Maybe a few more quickly follow.])**

**VOICEOVER:**
But here's the catch: Erwan's inbox is constantly flooded with these alerts! 'High severity vulnerability in package X,' 'Critical update for library Y.' The sheer volume is overwhelming. Erwan starts to wonder, 'Are all of these *really* a problem for *my* specific project? Is this vulnerable function even being used?'

**(VISUAL CUE: [Show Erwan looking stressed or dismissively waving at the screen full of alerts. Zoom in on one alert, then show a question mark over it, then Erwan shrugging and closing the email/notification.])**

**VOICEOVER:**
Eventually, this flood of information, where most alerts might not be directly exploitable in Erwan's context, leads to alert fatigue. And what happens? Erwan starts to ignore them. We've all been there, right? But this means real, potentially critical issues might slip through the cracks.

---

**SCENE 3: INTRODUCING AGENTPIMENTBLEU - THE SOLUTION**

**VOICEOVER (Transition - tone shifts to hopeful, solution-oriented):**
This is exactly the problem I wanted to solve with my hackathon project. What if there was a smarter way to analyze these vulnerabilities, one that understands *your* code and tells you what *actually* matters? That's where **AgentPimentBleu** comes in!

**(VISUAL CUE: [AgentPimentBleu logo/title card appears briefly, maybe with a little 🌶️ animation])**

**VOICEOVER:**
AgentPimentBleu isn't just another CVE lister. It's an AI-powered agent designed to intelligently scan your Git repositories, focusing on the *actual impact* of vulnerabilities within your project's unique context. It helps you filter out the noise and prioritize real risks.

---

**SCENE 4: DEMO - UI & FEATURES**

**(VISUAL CUE: [Transition to a screen recording of the AgentPimentBleu Gradio UI. Start with the clean input field.])**

**VOICEOVER:**
Let's take a quick tour. Here's the Gradio interface. It’s straightforward: you provide a Git repository URL or select one of the example projects provided.

**(VISUAL CUE: [Mouse cursor pastes a Git repository URL into the input field, or clicks on one of the `gr.Examples` for a pre-filled example like `examples/javascript_vulnerable_project`.])**

**VOICEOVER:**
AgentPimentBleu supports both Python and JavaScript projects. Before we scan, you'll notice some settings on the left. Here, you can override API keys for LLM providers like Gemini or Mistral if you want to use specific models, and also adjust parameters like the analysis graph's recursion limit for more complex projects.

**(VISUAL CUE: [Briefly hover over the API key input fields and the recursion limit slider, showing them being interacted with slightly.])**

**VOICEOVER:**
Once you're ready, you hit 'Scan Repository'.

**(VISUAL CUE: [Click the "Scan Repository" button. Show the status bar updating: "Initializing scan...", "Cloning repository...", "Analyzing dependencies...", "LLM analysis in progress..."])**

**VOICEOVER:**
Under the hood, AgentPimentBleu gets to work. First, it identifies your project's dependencies and any known CVEs. But then, the AI magic begins! It uses Large Language Models to understand the nitty-gritty of each CVE. Crucially, it also uses a technique called Retrieval Augmented Generation, using LlamaIndex, to build an index of your actual project code. This allows it to search your codebase for any real usage of the vulnerable components.

**(VISUAL CUE: [Could show a stylized graphic: Git repo icon -> Dependency files -> CVE database icon -> LLM icon analyzing CVE -> Code files being scanned -> LLM icon assessing impact. Keep it quick and abstract.])**

**VOICEOVER:**
After the analysis, which might take a moment for larger projects or complex vulnerabilities, the results are displayed. You get a clear summary, including a visual chart of vulnerability severity.

**(VISUAL CUE: [Results section appears. Show the vulnerability distribution chart, then switch to the "Summary" tab in the results.])**

**VOICEOVER:**
The real power comes when you dive into the 'Vulnerability Details' tab. For each identified vulnerability, AgentPimentBleu doesn't just tell you it exists; it provides an AI-generated assessment of its impact *in your project*, evidence from your code if the vulnerable part is used, and a proposed fix.

**(VISUAL CUE: [Switch to the "Vulnerability Details" tab. Scroll through a couple of example vulnerabilities. Highlight key sections like "AI Impact Assessment," "Evidence," and "Danger Rating." Zoom in slightly on a code snippet in the "Evidence" section.])**

**VOICEOVER:**
So, instead of just seeing a CVE for 'lodash', you'll see *if and how* your project uses the specific vulnerable lodash function, and what that means for *you*. It even supports `.apbignore` files, similar to `.gitignore`, so you can tell it to skip indexing things like build artifacts, keeping the analysis focused and efficient.

**(VISUAL CUE: [Show an example of a clear impact summary for one vulnerability, then maybe a quick flash of the Raw JSON tab.])**

---

**SCENE 5: CONCLUSION & PERSONAL TOUCH**

**VOICEOVER (Conclusion - tone becomes reflective, then appreciative):**
With AgentPimentBleu, the goal is to transform that overwhelming flood of alerts into a manageable, prioritized list of actionable security insights. So, developers like Erwan can spend less time chasing ghosts and more time fixing what truly matters.

**(VISUAL CUE: [Transition back to a concluding slide with the AgentPimentBleu logo, your name, and perhaps the hackathon logo.])**

**VOICEOVER:**
My name is Brieuc Crosson, and I'm a 21-year-old computer engineering student in France. This project, AgentPimentBleu, is actually my first-ever hackathon entry and also my first deep dive into building an AI-based project! It's been an incredibly fun and challenging experience, and I've learned so much.

I would absolutely love any feedback you might have – on the project, the idea, anything – as I'm always looking to improve. This hackathon has been a blast, and I'll surely be looking out for the next one!

Thank you so much for watching, and for being part of this amazing hackathon community!

**(MUSIC: Upbeat, slightly techy, outro music - fades back in and plays out)**

---