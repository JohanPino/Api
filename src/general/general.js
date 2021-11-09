import { serverMessages } from "./constans/serverMessages.js";

export const userManagementStatus = {
    doesNotExist: 0,
    wrongLoginData: 1,
    emailExists: 2,
    correctLoginData: 3,
    passwordExist: 4
}

export const serverMessagesToUser = {
    readMessage(keymsg, traza = "") {
        try {
            let data = {
                id: '0000',
                description: "",
                status: ""
            };
            Object.keys(serverMessages).forEach(function (key) {
                var value = serverMessages[key];
                if (value.id == keymsg) {
                    if (traza != "") {
                        value.traza = traza;
                        data = value;
                    } else {
                        data = value;
                    }
                } else {
                    return "";
                }

            });
            return data;
        } catch (error) {
            console.log(error);
        }
    }
}


export const encryptSha256 = async (message) => {

}