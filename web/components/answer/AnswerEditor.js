import React, { useState, useEffect, useCallback } from 'react';

import { QuestionType, StudentFilePermission } from '@prisma/client';

import TrueFalse from '../question/type_specific/TrueFalse';
import MultipleChoice from '../question/type_specific/MultipleChoice';
import Essay from '../question/type_specific/Essay';
import Code from '../question/type_specific/Code';
import Web from '../question/type_specific/Web';
import {Box, IconButton, Stack, Typography} from "@mui/material";
import FileEditor from "../question/type_specific/code/files/FileEditor";
import Image from "next/image";
import CodeCheck from "../question/type_specific/code/CodeCheck";
import useSWR from "swr";
import {useSnackbar} from "../../context/SnackbarContext";
import {useDebouncedCallback} from "use-debounce";

const AnswerEditor = ({ question, onAnswer }) => {

    return (
        question && (
            question.type === QuestionType.trueFalse && (
                <AnswerTrueFalse
                    question={question}
                    onAnswerChange={onAnswer}
                />
            )
            ||
            question.type === QuestionType.multipleChoice && (
                <AnswerMultipleChoice
                    question={question}
                    onAnswerChange={onAnswer}
                />
            )
            ||
            question.type === QuestionType.essay && (
                <AnswerEssay
                    question={question}
                    onAnswerChange={onAnswer}
                />
            )
            ||
            question.type === QuestionType.code && (
                <AnswerCode
                    question={question}
                    onAnswerChange={onAnswer}
                />
            )
            ||
            question.type === QuestionType.web && (
                <AnswerWeb
                    question={question}
                    onAnswerChange={onAnswer}
                />
            )
        )
    )
}


const AnswerCode  = ({ question, onAnswerChange }) => {

    const { showTopRight: showSnackbar } = useSnackbar();

    const { data:answer, mutate } = useSWR(
        `/api/answer/${question?.id}`,
        question.id ? (...args) => fetch(...args).then((res) => res.json()) : null,
    );

   const onFileChange = useCallback(async (file) => {
       await fetch(`/api/answer/${question.id}/code/${file.id}`, {
           method: 'PUT',
           headers: {
               'Content-Type': 'application/json'
           },
           body: JSON.stringify({file})
       });
       onAnswerChange && onAnswerChange();
    }, [question, mutate, onAnswerChange]);

    const debouncedOnChange = useDebouncedCallback(onFileChange, 500);

    return (
        answer?.code && (
            <Stack position="relative" height="100%">
                <Box height="100%" overflow="auto" pb={16}>
                    { answer.code.files?.map((answerToFile, index) => (
                        <FileEditor
                            key={index}
                            file={answerToFile.file}
                            readonlyPath
                            readonlyContent={answerToFile.studentPermission === StudentFilePermission.VIEW}
                            secondaryActions={
                                answerToFile.studentPermission === StudentFilePermission.VIEW && (
                                    <Stack direction="row" spacing={1} alignItems="center">
                                        <Image src="/svg/icons/viewable.svg" width={24} height={24} minWidth={24} />
                                        <Typography variant="caption">view</Typography>
                                    </Stack>
                                ) ||
                                answerToFile.studentPermission === StudentFilePermission.UPDATE && (
                                    <Stack direction="row" spacing={1}  alignItems="center">
                                        <Image src="/svg/icons/editable.svg" width={24} height={24} minWidth={24} />
                                        <Typography variant="caption">edit</Typography>
                                    </Stack>
                                )
                            }

                            onChange={debouncedOnChange}

                        />
                    ))}
                </Box>

                <Stack zIndex={2} position="absolute" maxHeight="100%" width="100%" overflow="auto" bottom={0} left={0}>
                    <CodeCheck
                        fetchSandbox={() => fetch(`/api/sandbox/${question.id}/student`, {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' }
                        })}
                    />
                </Stack>
            </Stack>
        )
    )
}

const AnswerMultipleChoice = ({ question, onAnswerChange }) => {
    const { showTopRight: showSnackbar } = useSnackbar();

    const { data:answer, mutate } = useSWR(
        `/api/answer/${question?.id}`,
        question.id ? (...args) => fetch(...args).then((res) => res.json()) : null,
    );

    const [ options, setOptions ] = useState(undefined);

    useEffect(() => {
        if(question.multipleChoice?.options && answer){
            // merge the options with the student answer

            let allOptions = question.multipleChoice.options;
            let studentOptions = answer.multipleChoice?.options;

            setOptions(allOptions.map(option => {
                return {
                    ...option,
                    isCorrect: studentOptions && studentOptions.some(studentOption => studentOption.id === option.id)
                }
            }));

        }
    }, [answer]);

    const onOptionChange = useCallback(async (options, index) => {
        const changedOption = options[index];
        const method = changedOption.isCorrect ? 'POST' : 'DELETE';
        await fetch(`/api/answer/${question.id}/multi-choice/options`, {
            method: method,
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ option: changedOption })
        });
        onAnswerChange && onAnswerChange();
    }, [question, mutate, onAnswerChange]);

    return(
        answer?.multipleChoice && options && (
        <MultipleChoice
            id={`answer-editor-${question.id}`}
            selectOnly
            options={options}
            onChange={onOptionChange}
        />
        )
    )
}

const AnswerTrueFalse = ({ question, onAnswerChange }) => {
    const { showTopRight: showSnackbar } = useSnackbar();

    const { data:answer, mutate } = useSWR(
        `/api/answer/${question?.id}`,
        question.id ? (...args) => fetch(...args).then((res) => res.json()) : null,
    );

    const onTrueFalseChange = useCallback(async (isTrue) => {
        await fetch(`/api/answer/${question.id}/true-false`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ isTrue })
        });
        onAnswerChange && onAnswerChange();
    }, [question, mutate, onAnswerChange]);

    return (
        answer?.trueFalse && (
            <TrueFalse
                id={`answer-editor-${question.id}`}
                allowUndefined={true}
                isTrue={answer.trueFalse.isTrue}
                onChange={onTrueFalseChange}
            />
        )
    )
}

const AnswerEssay = ({ question, onAnswerChange }) => {
    const { showTopRight: showSnackbar } = useSnackbar();

    const { data:answer, mutate } = useSWR(
        `/api/answer/${question?.id}`,
        question.id ? (...args) => fetch(...args).then((res) => res.json()) : null,
    );

    const onEssayChange = useCallback(async (content) => {
        await fetch(`/api/answer/${question.id}/essay`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ content })
        });
        onAnswerChange && onAnswerChange();
    }, [question, mutate, onAnswerChange]);

    const debouncedOnChange = useDebouncedCallback(onEssayChange, 500);

    return (
        answer?.essay && (
            <Essay
                id={`answer-editor-${question.id}`}
                content={answer.essay.content}
                onChange={debouncedOnChange}
            />
        )
    )
}

const AnswerWeb = ({ question, onAnswerChange }) => {
    const { showTopRight: showSnackbar } = useSnackbar();

    const { data:answer, mutate } = useSWR(
        `/api/answer/${question?.id}`,
        question.id ? (...args) => fetch(...args).then((res) => res.json()) : null,
    );

    const onWebChange = useCallback(async (web) => {
        await fetch(`/api/answer/${question.id}/web`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ web })
        });
        onAnswerChange && onAnswerChange();
    }, [question, mutate, onAnswerChange]);

    const debouncedOnChange = useDebouncedCallback(onWebChange, 500);

    return (
        answer?.web && (
            <Web
                id={`answer-editor-${question.id}`}
                web={answer.web}
                onChange={debouncedOnChange}
            />
        )
    )
}

export default AnswerEditor;
