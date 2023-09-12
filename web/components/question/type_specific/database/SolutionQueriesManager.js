import useSWR from "swr";
import {fetcher} from "../../../../code/utils";
import Loading from "../../../feedback/Loading";
import {
    Button,
    Stack, Typography,
    useTheme,
} from "@mui/material";
import React, {useCallback, useEffect, useRef, useState} from "react";
import ScrollContainer from "../../../layout/ScrollContainer";

import {useDebouncedCallback} from "use-debounce";

import QueryOutput from "./QueryOutput";
import QueryUpdatePanel from "./QueryUpdatePanel";
import QueryEditor from "./QueryEditor";
import DateTimeAgo from "../../../feedback/DateTimeAgo";


const SolutionQueriesManager = ({ questionId }) => {
    const theme = useTheme()

    const ref = useRef()

    const {
        data,
        mutate,
        error,
    } = useSWR(
        `/api/questions/${questionId}/database/queries`,
        questionId ? fetcher : null,
        { revalidateOnFocus: false }
    )

    const [ queries, setQueries ] = useState()
    const [ outputs, setOutputs ] = useState()
    const [ activeQuery, setActiveQuery ] = useState(null)

    useEffect(() => {
        if(!data) return
        // remove outputs from queries, outputs are managed in a separate state
        setQueries(data.map((q) => q.query))
        setOutputs(data.map((q) => q.output))
    }, [data]);

    const onAddQuery = useCallback(async () => {
        await fetch(`/api/questions/${questionId}/database/queries`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
            },
        }).then(async () => {
            await mutate();
            ref.current.scrollTop = ref.current.scrollHeight
        });
    }, [queries, mutate])

    const onQueryUpdate = useCallback( async (query, doMutate = false) => {
        console.log("onQueryUpdate", query)
        await fetch(`/api/questions/${questionId}/database/queries/${query.id}`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
            },
            body: JSON.stringify(query),
        }).then(async () => {
            if(!doMutate) {
                const queryRef = queries.find((q) => q.id === query.id);
                if (!queryRef) {
                    return;
                }
                // update in memory to avoid re-fetching and re-rendering the full list of queries
                queryRef.title = query.title;
                queryRef.description = query.description;
                queryRef.lintRules = query.lintRules;
                queryRef.content = query.content;
                queryRef.template = query.template;
                queryRef.queryOutputTests = query.queryOutputTests;
            }else{
                await mutate();
            }

        });
    }, [queries, questionId, mutate]);

    const debouncedOnQueryUpdate = useDebouncedCallback((q, m) => onQueryUpdate(q, m), 500)

    const onQueryDelete = useCallback(async (query) => {
        await fetch(`/api/questions/${questionId}/database/queries/${query.id}`, {
            method: 'DELETE',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
            },
        }).then(async () => {
            await mutate();
        });
    }, [queries, mutate, questionId]);

    const runAllQueries = useCallback(async () => {
        // erase eventual previous outputs
        setOutputs(queries.map((q, index) => ({
            ...outputs[index],
            output:{
                ...outputs[index]?.output,
                result: null,
                status: "RUNNING",
            }
        })) || []);

        const newOutputs = await fetch(`/api/sandbox/${questionId}/database`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
            },
        }).then((res) => res.json());

        // set all query outputs
        setOutputs(newOutputs);

    }, [questionId, outputs, queries]);



    const getBorderStyle = useCallback((index) => {
        return index === activeQuery ? theme.palette.primary.dark : "transparent";
    }, [activeQuery, theme]);

    return (
        <Loading loading={!queries} errors={[error]}>
        <Stack
            position={'relative'}
            height={'100%'}
            overflow={'hidden'}
            pb={'60px'}
        >
                <Stack direction={"row"} spacing={1} alignItems={"center"} justifyContent={"space-between"} p={1}>
                    <Button variant={"outlined"} color={"info"} onClick={() => runAllQueries()}>
                        Run all
                    </Button>
                    <Button onClick={onAddQuery}>Add new query</Button>
                </Stack>
                <ScrollContainer ref={ref}>
                    {queries?.map((query, index) => (
                        <Stack position="relative" onClick={() => setActiveQuery(index)} sx={{
                            cursor: "pointer",
                            borderLeft: `3px solid ${getBorderStyle(index)}`,
                        }}>
                            <QueryEditor
                                active={index === activeQuery}
                                key={query.id}
                                query={query}
                                onChange={(q) => debouncedOnQueryUpdate(q)}
                            />
                            <QueryOutput
                                header={
                                    <>
                                        <Typography variant={"caption"}>Last run:</Typography>
                                        {outputs[index]?.updatedAt && <DateTimeAgo date={new Date(outputs[index].updatedAt)} />}
                                    </>
                                }
                                result={outputs[index].output}
                            />
                        </Stack>
                    ))}
                </ScrollContainer>
                {
                    queries?.length > 0 && activeQuery !== null && (
                        <QueryUpdatePanel
                            query={queries[activeQuery]}
                            output={outputs[activeQuery]}
                            onChange={(q) => debouncedOnQueryUpdate(q, true)}
                            onDelete={(q) => onQueryDelete(q)}
                        />
                    )
                }
        </Stack>
        </Loading>
    )
}




export default SolutionQueriesManager
