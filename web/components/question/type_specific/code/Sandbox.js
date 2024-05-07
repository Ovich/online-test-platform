/**
 * Copyright 2022-2024 HEIG-VD
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
import React, { useCallback, useEffect, useState } from 'react'
import { useDebouncedCallback } from 'use-debounce'
import { Box, IconButton, Stack, TextField, Tooltip, Typography } from '@mui/material'
import useSWR from 'swr'
import Loading from '@/components/feedback/Loading'
import { fetcher } from '@/code/utils'
import StatusDisplay from '@/components/feedback/StatusDisplay'
import { useSnackbar } from '@/context/SnackbarContext'
const Sandbox = ({ groupScope, questionId, onUpdate }) => {
  const { data: sandbox, error } = useSWR(
    `/api/${groupScope}/questions/${questionId}/code/sandbox`,
    groupScope && questionId ? fetcher : null,
    { revalidateOnFocus: false },
  )

  const { show: showSnackbar } = useSnackbar()

  const [image, setImage] = useState(sandbox?.image || '')
  const [beforeAll, setBeforeAll] = useState(sandbox?.beforeAll || '')
  const [ pullStatus, setPullStatus ] = useState('RELOAD')

  useEffect(() => {
    setImage(sandbox?.image || '')
    setBeforeAll(sandbox?.beforeAll || '')
  }, [sandbox])

  const onChange = useCallback(
    async (sandbox) => {
      await fetch(`/api/${groupScope}/questions/${questionId}/code/sandbox`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json',
        },
        body: JSON.stringify({
          ...sandbox,
        }),
      }).finally(() => {
        onUpdate && onUpdate()
      })
    },
    [groupScope, questionId, onUpdate],
  )

  const debouncedOnChange = useDebouncedCallback(onChange, 500)

  const pullImage = async (image) => {
    setPullStatus("LOADING")
    await fetch(`/api/sandbox/image/pull`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify({
        image: image,
      }),
    })
    .then((data) => data.json())
    .then((data) => {
      setPullStatus(data.status)
      const severity = data.status === 'SUCCESS' ? 'success' : 'error'
      showSnackbar(data.message, severity)
      // Set to RELOAD after 2 seconds
      setTimeout(() => {
        setPullStatus("RELOAD")
      }, 2000)
    })
    
  }


  return (
    <Loading loading={!sandbox} errors={[error]}>
      <Stack spacing={2}>
        <Typography variant="h6">Sandbox</Typography>
        <Stack direction="row" spacing={2}>
          <TextField
            id="image"
            label="Image"
            variant="standard"
            value={image}
            fullWidth
            onChange={(ev) => {
              setImage(ev.target.value)
              debouncedOnChange({
                ...sandbox,
                image: ev.target.value,
              })
            }}
            InputProps={{
              endAdornment: (
                <Tooltip title="Pull the latest version">
                  <Box ml={0.5}>
                    <IconButton
                        edge="end"
                        aria-label="pull"
                        size='small'
                        onClick={() => pullImage(image)}
                    >
                    <StatusDisplay
                      status={pullStatus}
                    />  
                    </IconButton>
                  </Box>
                </Tooltip>
              ),
            }}
          />
          
          <TextField
            id="compile"
            label="Before All"
            variant="standard"
            value={beforeAll}
            fullWidth
            multiline
            onChange={(ev) => {
              setBeforeAll(ev.target.value)
              debouncedOnChange({
                ...sandbox,
                beforeAll: ev.target.value,
              })
            }}
          />
        </Stack>
      </Stack>
    </Loading>
  )
}

export default Sandbox
