import useSWR from "swr";
import {Box, Button, MenuItem, Stack} from "@mui/material";
import FileEditor from "./FileEditor";
import { updateFile } from "./crud";
import DropDown from "../../../../input/DropDown";
import {StudentFilePermission} from "@prisma/client";
import React, {useCallback} from "react";

const TemplateFilesManager = ({ question }) => {

    const { data: files, mutate, error } = useSWR(
        `/api/questions/${question.id}/code/files/template`,
        question?.id ? (...args) => fetch(...args).then((res) => res.json()) : null,
        { revalidateOnFocus: false }
    );

    const onFileUpdate = useCallback(async (file) => {
        await updateFile("template", question.id, file).then(async () => await mutate());
    }, [question.id, mutate, files]);

    return (
        <Stack height="100%">
            <Button onClick={() => {}}>Pull Solution</Button>
            {files && (
                <Box height="100%" overflow="auto">
                    {files.map((file, index) => (
                        <FileEditor
                            key={index}
                            file={file}
                            onChange={async (file) => await onFileUpdate(file)}
                            secondaryActions={
                                <Stack direction="row" spacing={1}>
                                    <DropDown
                                        id={`${file.id}-student-permission`}
                                        name="Student Permission"
                                        defaultValue={file.studentPermission}
                                        minWidth="200px"
                                        onChange={async (permission) => {
                                            file.studentPermission = permission;
                                            await onFileUpdate(file);
                                        }}
                                    >
                                        <MenuItem value={StudentFilePermission.UPDATE}>Update</MenuItem>
                                        <MenuItem value={StudentFilePermission.VIEW}>View</MenuItem>
                                        <MenuItem value={StudentFilePermission.HIDDEN}>Hidden</MenuItem>
                                    </DropDown>
                                </Stack>
                            }
                        />
                    ))}
                </Box>
            )}
        </Stack>
    )
}

export default TemplateFilesManager;
