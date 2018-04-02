package procmon

type Process struct {
	ID   int
	Path string
	Args []string
}

func NewProcess(pid int, path string) *Process {
	return &Process{
		ID:   pid,
		Path: path,
		Args: make([]string, 0),
	}
}
