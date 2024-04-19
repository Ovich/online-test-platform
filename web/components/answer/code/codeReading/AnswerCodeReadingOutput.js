import React, { useEffect, useState } from 'react';
import { Box, InputAdornment, TextField } from '@mui/material';
import InlineMonacoEditor from '@/components/input/InlineMonacoEditor';

import { styled } from '@mui/system';

// Styled component to apply whitespace visibility
const MonoSpaceTextField = styled(TextField)({
  '& textarea': {
    whiteSpace: 'pre-wrap', // Preserves whitespaces and wraps text
    fontFamily: 'monospace' // Makes spaces more noticeable
  }
});

const AnswerCodeReadingOutput = ({ language, snippet, output:initial, status, onOutputChange }) => {

    const [ output, setOutput ] = useState(initial);
  
    useEffect(() => {
      setOutput(initial);
    }, [initial]);
  
    return (
      <Box>
        <InlineMonacoEditor
          readOnly
          language={language}
          minHeight={30}
          code={snippet}
        />
        <Box p={1}>
          <MonoSpaceTextField
            variant="standard"
            label="Guess the output"
            fullWidth
            multiline
            value={output || ''}
            onChange={(e) => {
              setOutput(e.target.value)
              onOutputChange(e.target.value)
            }}
            placeholder='...'
            helperText="Supports multiple lines. Careful with whitespaces."
            InputProps={{
              startAdornment: (
                <InputAdornment position="start">
                  <Box pt={0.5}>
                    {status}
                  </Box>
                </InputAdornment>
              ),
            }}
          />
        </Box>
  
      </Box>
    );
  }

export default AnswerCodeReadingOutput;