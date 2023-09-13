import {
    Alert, Badge, Box, Divider,
    Stack,
    Table,
    TableBody,
    TableCell,
    TableContainer,
    TableHead,
    TableRow, Tooltip,
    Typography, useTheme
} from "@mui/material";
import { useEffect, useRef} from "react";
import {useDebouncedCallback} from "use-debounce";
import {DatabaseQueryOutputStatus} from "@prisma/client";
import StatusDisplay from "../../../feedback/StatusDisplay";

const ViolationSummary = ({violation}) => {
    return(
        <Stack>
            <Typography variant={"caption"}>{`${violation?.description} (${violation?.code})`}</Typography>
            {violation?.lines?.map((line) => (
                <Typography variant={"caption"}>{`Line ${line.line} pos ${line.pos}`}</Typography>
            ))}
        </Stack>
    )
}
const QueryOutput = ({ header, color, result, lintResult, onHeightChange }) => {

    const containerRef = useRef(null);

    const debouncedHeightChange = useDebouncedCallback((h) => onHeightChange(h), 100)

    useEffect(() => {
        if (onHeightChange && containerRef.current) {
            const observer = new ResizeObserver(() => {
                debouncedHeightChange(containerRef.current?.getBoundingClientRect().height);
            });
            observer.observe(containerRef.current);

            // Cleanup observer on component unmount
            return () => observer.disconnect();
        }
    }, [debouncedHeightChange]);

    const renderQueryOutput = (output) => {
        if(!output.result) return null
        switch (output.type) {
            case "SCALAR":
            // return <QueryOutputScalar dataset={output.result} />
            case "TABULAR":
                return <QueryOutputTabular dataset={output.result} />
            case "TEXT":
                return <QueryOutputText feedback={output.feedback} />
            default:
                return null
        }
    }

    const severity = (status) => {
        switch (status) {
            case "SUCCESS":
                return color || "success"
            case "ERROR":
                return "error"
            case "WARNING":
                return "warning"
            case "RUNNING":
                return "info"
            default:
                return "info"
        }
    }

    return (
        result && (
            <Alert icon={false} severity={severity(result.status)} ref={containerRef}>
                <Stack spacing={1}>
                    <Stack direction={"row"} spacing={1} alignItems={"center"}>
                        {header}
                    </Stack>
                    <Stack direction={"row"} spacing={1}>
                        {result.status === DatabaseQueryOutputStatus.RUNNING && <StatusDisplay status={DatabaseQueryOutputStatus.RUNNING} />}
                        {renderQueryOutput(result)}
                    </Stack>
                    <LintResult lintResult={lintResult} />
                </Stack>
            </Alert>
        )
    );
}

const LintResult = ({ lintResult }) => {
    return (
        lintResult && (
            <Stack direction={"row"} spacing={1}>
                <Typography variant={"body2"}>Linter</Typography>
                <Box ml={1}>
                    {
                        lintResult?.violations?.length === 0 && (
                            <StatusDisplay status={"SUCCESS"} />
                        )
                        ||
                        lintResult?.violations?.length > 0 && (
                            <StatusDisplay status={"WARNING"} />
                        )
                    }
                </Box>
                {
                    lintResult?.violations?.length > 0 && (
                        <>
                            <Divider variant={"middle"} orientation={"vertical"} flexItem={true} />
                            <Stack direction={"row"} spacing={2}>
                                {lintResult?.violations?.map((violation) => (
                                    <Badge badgeContent={violation?.lines?.length || 0} color="info">
                                        <Tooltip
                                            title={
                                                <ViolationSummary violation={violation} />
                                            }
                                            placement={"bottom"}
                                        >
                                            <Stack direction={"row"} spacing={1} pr={1}>
                                                <Typography variant={"caption"}>{violation?.code}</Typography>
                                            </Stack>
                                        </Tooltip>
                                    </Badge>
                                ))}
                            </Stack>
                        </>

                    )
                }
            </Stack>
        )
    )
}
const QueryOutputTabular = ({ dataset }) => {
    const theme = useTheme();

    return (
        <Stack spacing={1}>
        <TableContainer sx={{
            height: 'max-content',
            maxHeight: "350px",
            maxWidth: "100%"
        }}>
            <Table
                size="small"
                sx={{
                    width: 'max-content',
                    borderLeft: `1px solid ${theme.palette.divider}`,
                    borderTop: `1px solid ${theme.palette.divider}`,
                    overflow: 'hidden',
                }}
            >
                <TableHead>
                    <TableRow>
                        {dataset.columns.map((col, index) => (
                            <TableCell
                                key={index}
                                variant="head"
                                sx={{
                                    minWidth: 'min-content',
                                    maxWidth: '350px',
                                    whiteSpace: 'nowrap',
                                    overflow: 'hidden',
                                    textOverflow: 'ellipsis',
                                    borderRight: `1px solid ${theme.palette.divider}`,
                                    borderBottom: `1px solid ${theme.palette.divider}`
                                }}
                            >
                                {col.name}
                            </TableCell>
                        ))}
                    </TableRow>
                </TableHead>
                <TableBody>
                    {dataset.rows.map((row, rowIndex) => (
                        <TableRow key={rowIndex}>
                            {row.map((value, colIndex) => (
                                <TableCell
                                    key={colIndex}
                                    sx={{
                                        minWidth: 'min-content',
                                        maxWidth: '350px',
                                        whiteSpace: 'nowrap',
                                        overflow: 'hidden',
                                        textOverflow: 'ellipsis',
                                        borderRight: `1px solid ${theme.palette.divider}`,
                                        borderBottom: `1px solid ${theme.palette.divider}`
                                    }}
                                >
                                    {value}
                                </TableCell>
                            ))}
                        </TableRow>
                    ))}
                </TableBody>
            </Table>

        </TableContainer>
        <Typography variant="caption">Row Count: {dataset.rows.length}</Typography>
    </Stack>
    )
}


const QueryOutputScalar = ({ dataset }) => {
    return (
        <Typography variant="body1">{dataset.rows[0]}</Typography>
    )
}

const QueryOutputText = ({ feedback }) => {
    return (
        <Typography variant="body1">{feedback}</Typography>
    )
}

export default QueryOutput;
