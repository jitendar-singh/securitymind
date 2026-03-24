import { useState } from "react";
import "./App.css";
import { CopilotKit } from "@copilotkit/react-core";
import { CopilotTextarea } from "@copilotkit/react-textarea";
import { CopilotPopup } from "@copilotkit/react-ui";

const App = () => {
  const [text, setText] = useState("");

  return (
    <CopilotKit url="http://localhost:8000/copilotkit">
      <CopilotPopup
        instructions="Help me with my code"
        defaultOpen={true}
        labels={{
          title: "SecMind Agent",
          initial: "Hi there! How can I help you?",
        }}
        >
        <div className="App">
          <CopilotTextarea
            className="w-full h-40"
            value={text}
            onValueChange={(value) => setText(value)}
            placeholder="What are you working on?"
            autosuggestions={{
              purpose: "to help the user write code",
            }}
          />
        </div>
      </CopilotPopup>
    </CopilotKit>
  );
};

export default App;
