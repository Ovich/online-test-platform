import useSWR from "swr";
import {fetcher} from "../../../code/utils";
import React, {useCallback, useRef, useState} from "react";
import {useDebouncedCallback} from "use-debounce";
import Loading from "../../feedback/Loading";
import {Stack, Typography} from "@mui/material";
import ScrollContainer from "../../layout/ScrollContainer";
import FileEditor from "../../question/type_specific/code/files/FileEditor";
import {StudentPermission} from "@prisma/client";
import Image from "next/image";
import CodeCheck from "../../question/type_specific/code/CodeCheck";
import StudentPermissionIcon from "../../feedback/StudentPermissionIcon";




const AnswerCode = ({ jamSessionId, questionId, onAnswerChange }) => {
    const { data: answer, error } = useSWR(
        `/api/jam-sessions/${jamSessionId}/questions/${questionId}/answers`,
        questionId ? fetcher : null,
        { revalidateOnFocus: false }
    )

    const ref = useRef()

    const [ lockCodeCheck, setLockCodeCheck ] = useState(false)

    const onFileChange = useCallback(
        async (file) => {
            setLockCodeCheck(true)
            const currentFile = answer.code.files.find((f) => f.file.id === file.id)
            if (currentFile.file.content === file.content) return
            const updatedStudentAnswer = await fetch(
                `/api/jam-sessions/${jamSessionId}/questions/${questionId}/answers/code/${file.id}`,
                {
                    method: 'PUT',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ file }),
                }
            ).then((res) => res.json())
            setLockCodeCheck(false)
            onAnswerChange && onAnswerChange(updatedStudentAnswer)
        },
        [jamSessionId, questionId, answer, onAnswerChange]
    )

    const debouncedOnChange = useDebouncedCallback(onFileChange, 500)

    return (
        <Loading errors={[error]} loading={!answer}>
            {answer?.code && (
                <Stack
                    position={'relative'}
                    height={'100%'}
                    overflow={'hidden'}
                    p={1}
                    pb={'50px'}
                >
                    <ScrollContainer ref={ref}>
                        {answer.code.files?.map((answerToFile, index) => (
                            <FileEditor
                                key={index}
                                file={answerToFile.file}
                                readonlyPath
                                readonlyContent={
                                    answerToFile.studentPermission === StudentPermission.VIEW
                                }
                                leftCorner={
                                    <StudentPermissionIcon permission={answerToFile.studentPermission} />
                                }
                                onChange={(file) => {
                                    setLockCodeCheck(true)
                                    debouncedOnChange(file)
                                }}
                            />
                        ))}
                    </ScrollContainer>

                    <CodeCheck
                        lockCodeCheck={lockCodeCheck}
                        codeCheckAction={() =>
                            fetch(
                                `/api/sandbox/jam-sessions/${jamSessionId}/questions/${questionId}/student/code`,
                                {
                                    method: 'POST',
                                    headers: { 'Content-Type': 'application/json' },
                                }
                            )
                        }
                    />
                </Stack>

            )}
        </Loading>
    )
}

export default AnswerCode
