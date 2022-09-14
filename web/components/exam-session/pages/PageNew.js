import { useState } from 'react';
import { useRouter } from 'next/router'
import { ExamSessionPhase } from '@prisma/client';

import MainLayout from '../../layout/MainLayout';
import { Stepper, Step, StepLabel, Stack, Button  } from "@mui/material";
import { useSnackbar } from '../../../context/SnackbarContext';

import StepReferenceExam from '../draft/StepReferenceExam';

const PageNew = () => {
    const router = useRouter();
    const { show: showSnackbar } = useSnackbar();
    const [ questions, setQuestions ] = useState();

    const onChangeRefenceExam = (_, questions) => setQuestions(questions);

    const handleNext = async () => {
        if(!questions || questions && questions.length === 0){
            showSnackbar('You exam session has no questions. Please select the reference exam.', 'error');
            return;
        }      
        
        let response = await fetch('/api/exam-sessions', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
            },
            body: JSON.stringify({
                phase: ExamSessionPhase.DRAFT,
                questions
            })
        });
        
        let examSession = await response.json();
        router.push(`/exam-sessions/${examSession.id}/draft/1`);
    };

    return (
    <MainLayout>
    <Stack sx={{ minWidth:'800px' }} spacing={2}>
        <Stack direction="row" justifyContent="flex-end">
            <Button onClick={handleNext}>Next</Button>
        </Stack>
        <Stepper activeStep={0} orientation="vertical">
            
            <Step key="chose-exam">
                <StepReferenceExam 
                    onChange={onChangeRefenceExam}
                />
            </Step>    
            

            <Step key="chose-exam">
                <StepLabel>General Informations</StepLabel>
            </Step>
            
        </Stepper>      
        <Stack direction="row" justifyContent="flex-end">
            <Button onClick={handleNext}>Next</Button>
        </Stack>
    </Stack>
    </MainLayout>
    )
}




export default PageNew;