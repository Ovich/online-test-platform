import React, { useCallback, useEffect, useRef, useState } from 'react'
import Image from 'next/image'
import useSWR from 'swr'
import {
  Box,
  Button,
  IconButton,
  Stack,
  TextField,
  Typography,
  useTheme,
} from '@mui/material'
import { useDebouncedCallback } from 'use-debounce'
import languages from '../../../../code/languages.json'
import { fetcher } from '../../../../code/utils'
import ScrollContainer from '../../../layout/ScrollContainer'
import { useSnackbar } from '../../../../context/SnackbarContext'
import Loading from '../../../feedback/Loading'

const environments = languages.environments

const TestCases = ({ groupScope, questionId, language }) => {
  const { show: showSnackbar } = useSnackbar()
  const {
    data: tests,
    mutate,
    error,
  } = useSWR(
    `/api/${groupScope}/questions/${questionId}/code/tests`,
      groupScope && questionId ? fetcher : null,
    { revalidateOnFocus: false }
  )

  // react on the language change, re-fetch the tests
  useEffect(() => {
    ;(async () => await mutate())()
  }, [language, mutate])

  const addTestCase = useCallback(async () => {
    const exec =
      tests.length === 0
        ? environments.find((env) => env.language === language).sandbox.exec
        : tests[tests.length - 1].exec
    await fetch(`/api/${groupScope}/questions/${questionId}/code/tests`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify({
        input: '',
        expectedOutput: '',
        exec: exec,
      }),
    })
    await mutate()
  }, [groupScope, questionId, tests, mutate, language])

  const deleteTestCase = useCallback(
    async (index) => {
      await fetch(`/api/${groupScope}/questions/${questionId}/code/tests/${index}`, {
        method: 'DELETE',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json',
        },
      }).then(async (res) => {
        if (res.status === 200) {
          // filter test cases and decrement all indexes after the deleted one
          let newTests = tests
            .filter((test) => test.index !== index)
            .map((test) => {
              if (test.index > index) {
                test.index--
              }
              return test
            })
          await mutate(newTests)
        } else {
          showSnackbar('error', 'Failed to delete test case')
        }
      })
    },
    [groupScope, questionId, tests, mutate, showSnackbar]
  )

  const updateTestCase = useCallback(
    async (test) => {
      await fetch(`/api/${groupScope}/questions/${questionId}/code/tests/${test.index}`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json',
        },
        body: JSON.stringify({
          exec: test.exec,
          input: test.input,
          expectedOutput: test.expectedOutput,
        }),
      })
      await mutate()
    },
    [groupScope, questionId, mutate]
  )

  const pullOutputs = useCallback(
    async (source) => {
      const result = await fetch(`/api/sandbox/${questionId}/${source}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      }).then((res) => res.json())

      for (const test of tests) {
        await updateTestCase({
          ...test,
          expectedOutput: result.tests[test.index - 1].output,
        })
      }
    },
    [questionId, tests, updateTestCase]
  )
  return (
    <Loading loading={!tests} errors={[error]}>
      <Stack spacing={2} height={'100%'} flex={1} overflow={'hidden'}>
        <Stack direction="row" spacing={2} justifyContent="space-between">
          <Typography variant="h6">Test Cases</Typography>
          <Box>
            <Button onClick={() => pullOutputs('solution')}>
              Pull outputs from solution
            </Button>
            <Button color="primary" onClick={addTestCase}>
              Add new test case
            </Button>
          </Box>
        </Stack>

        <ScrollContainer spacing={2} pb={24}>
          {tests?.map((test, i) => (
            <TestCaseUpdate
              test={test}
              key={i}
              onChange={(updatedTest) => updateTestCase(updatedTest)}
              onDelete={() => deleteTestCase(test.index)}
            />
          ))}
        </ScrollContainer>
      </Stack>
    </Loading>
  )
}

const TestCaseUpdate = ({ test, onChange, onDelete }) => {
  const theme = useTheme()
  const [input, setInput] = useState(test.input || '')
  const [expectedOutput, setExpectedOutput] = useState(test.expectedOutput || '')
  const [exec, setExec] = useState(test.exec || '')

  useEffect(() => {
    setInput(test.input || '')
    setExpectedOutput(test.expectedOutput || '')
    setExec(test.exec || '')
  }, [test])

  const debouncedOnChange = useDebouncedCallback(onChange, 300)

  return (
    <Stack direction="row" spacing={2}>
      <Stack
        borderRight={`3px solid ${theme.palette.info.main}`}
        pr={1}
        height="100%"
        alignItems="center"
      >
        <Typography color={theme.palette.info.main} variant="body1">
          <b>{test.index}</b>
        </Typography>
      </Stack>
      <TextField
        id="exec"
        label="Exec"
        variant="standard"
        value={exec}
        onChange={(ev) => {
          setExec(ev.target.value)
          debouncedOnChange({ ...test, exec: ev.target.value })
        }}
      />
      <Stack direction="row" spacing={2} flexGrow={1}>
        <TextField
          id="input"
          label="Input"
          variant="standard"
          inputProps={{ style: { fontFamily: 'monospace' } }}
          multiline
          fullWidth
          value={input}
          onChange={(ev) => {
            setInput(ev.target.value)
            debouncedOnChange({ ...test, input: ev.target.value })
          }}
        />
        <TextField
          id="output"
          label="Output"
          inputProps={{ style: { fontFamily: 'monospace' } }}
          multiline
          fullWidth
          variant="standard"
          value={expectedOutput}
          onChange={(ev) => {
            setExpectedOutput(ev.target.value)
            debouncedOnChange({ ...test, expectedOutput: ev.target.value })
          }}
        />
      </Stack>
      <IconButton key="delete-test-case" onClick={() => onDelete(test.index)}>
        <Image
          alt="Delete"
          src="/svg/icons/delete.svg"
          layout="fixed"
          width="18"
          height="18"
        />
      </IconButton>
    </Stack>
  )
}

export default TestCases
